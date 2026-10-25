package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// markdownTargets scans inline links while skipping fenced code. Destinations
// may be enclosed in angle brackets or contain balanced parentheses.
func markdownTargets(prose string) []string {
	var targets []string

	for at := 0; at < len(prose); {
		if strings.HasPrefix(prose[at:], "```") {
			if end := strings.Index(prose[at+3:], "```"); end >= 0 {
				at += end + 6
				continue
			}
		}

		if prose[at] != '[' {
			at++
			continue
		}

		end := markdownEscapedEnd(prose, at+1, ']')
		if end+1 >= len(prose) || prose[end+1] != '(' {
			at = end
			continue
		}

		target, end, ok := markdownDestination(prose, end+2)
		if !ok {
			at = end
			continue
		}

		end = markdownLinkSuffix(prose, end)

		if end < len(prose) && prose[end] == ')' {
			targets = append(targets, target)
			end++
		}

		at = end
	}

	return targets
}

// markdownEscapedEnd skips escaped bytes while finding a label/title delimiter.
func markdownEscapedEnd(prose string, at int, delimiter byte) int {
	for at < len(prose) && prose[at] != delimiter {
		if prose[at] == '\\' && at+1 < len(prose) {
			at++
		}

		at++
	}

	return at
}

func markdownDestination(prose string, start int) (string, int, bool) {
	if start < len(prose) && prose[start] == '<' {
		start++

		end := start
		for end < len(prose) && prose[end] != '>' {
			end++
		}

		return prose[start:end], end, end < len(prose)
	}

	end := markdownBalancedEnd(prose, start)

	return prose[start:end], end, true
}

func markdownBalancedEnd(prose string, at int) int {
	depth := 0

	for at < len(prose) {
		c := prose[at]
		if c == '\\' && at+1 < len(prose) {
			at += 2
			continue
		}

		if c == '(' {
			depth++
		}

		if c == ')' {
			if depth == 0 {
				break
			}

			depth--
		}

		if markdownSpace(c) {
			break
		}

		at++
	}

	return at
}

func markdownLinkSuffix(prose string, end int) int {
	if end < len(prose) && prose[end] == '>' {
		end++
	}

	end = markdownSpaceEnd(prose, end)
	if end < len(prose) && prose[end] == '"' {
		end = markdownEscapedEnd(prose, end+1, '"')
		if end < len(prose) {
			end++
		}

		end = markdownSpaceEnd(prose, end)
	}

	return end
}

func markdownSpaceEnd(prose string, at int) int {
	for at < len(prose) && markdownSpace(prose[at]) {
		at++
	}

	return at
}

func markdownSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func localPath(root, base, target string) (string, error) {
	if filepath.IsAbs(target) {
		return "", errors.New("absolute path is not portable")
	}

	path, err := filepath.EvalSymlinks(filepath.Join(base, target))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path leaves the repository")
	}

	return path, nil
}

func checkDocs(root string, out io.Writer) error {
	documents, err := markdownDocuments(root)
	if err != nil {
		return err
	}

	var problems []error

	for _, path := range documents {
		data, err := os.ReadFile(path) // #nosec G304 -- Only repository Markdown paths are collected.
		if err != nil {
			return err
		}

		for _, target := range markdownTargets(string(data)) {
			if err := checkMarkdownTarget(root, path, target); err != nil {
				problems = append(problems, err)
			}
		}
	}

	data, err := os.ReadFile(filepath.Join(root, "docs", "conformance.json")) // #nosec G304 -- The conformance file has a fixed repository-relative path.
	if err != nil {
		return err
	}

	count, registerProblems, err := checkConformanceRegister(root, data)
	if err != nil {
		return err
	}

	problems = append(problems, registerProblems...)

	if err := errors.Join(problems...); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Documentation links and normative traceability checked (%d capability entries)\n", count)

	return err
}

func markdownDocuments(root string) ([]string, error) {
	documents, err := filepath.Glob(filepath.Join(root, "*.md"))
	if err != nil {
		return nil, err
	}

	for _, dir := range []string{"build", "tests"} {
		readmes, err := filepath.Glob(filepath.Join(root, dir, "*.md"))
		if err != nil {
			return nil, err
		}

		documents = append(documents, readmes...)
	}

	err = filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Ext(path) == ".md" {
			documents = append(documents, path)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	return documents, nil
}

func checkMarkdownTarget(root, path, target string) error {
	if filepath.IsAbs(filepath.FromSlash(target)) && !strings.HasPrefix(target, "//") {
		return fmt.Errorf("%s: absolute link %q is not portable", path, target)
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("%s: invalid link %q", path, target)
	}

	if u.Scheme != "" || u.Host != "" || u.Path == "" {
		return nil
	}

	if _, err := localPath(root, filepath.Dir(path), filepath.FromSlash(u.Path)); err != nil {
		return fmt.Errorf("%s: broken/nonportable link %q: %w", path, target, err)
	}

	return nil
}

func checkConformanceTest(root, name string) error {
	path, err := localPath(root, root, filepath.FromSlash(name))
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("test path is not a regular file")
	}

	return nil
}
