/* Independent TEST harness using libxml2's XPath + C14N implementation.
 * Never linked into the Go module. All input is local, bounded test data;
 * DTD-bearing input and external entity loading are rejected. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/c14n.h>

static xmlParserInputPtr deny_external(const char *url, const char *id, xmlParserCtxtPtr ctx) {
    (void)url; (void)id; (void)ctx; return NULL;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) { puts(xmlParserVersion); return 0; }
    if (argc < 6) { fputs("usage: oracle FILE MODE COMMENTS XPATH PREFIX...\n", stderr); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
    long size = ftell(f);
    if (size < 0 || size > 8 * 1024 * 1024) { fclose(f); return 2; }
    rewind(f);
    char *data = malloc((size_t)size + 1);
    if (!data || fread(data, 1, (size_t)size, f) != (size_t)size) { free(data); fclose(f); return 2; }
    fclose(f);
    xmlSetExternalEntityLoader(deny_external);
    xmlDocPtr doc = xmlReadMemory(data, (int)size, NULL, NULL, XML_PARSE_NONET);
    free(data);
    if (!doc || doc->intSubset || doc->extSubset) { if (doc) xmlFreeDoc(doc); return 3; }
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr obj = NULL;
    if (strcmp(argv[4], "-") != 0) {
        obj = xmlXPathEvalExpression((const xmlChar *)argv[4], ctx);
        if (!obj || obj->type != XPATH_NODESET) { xmlXPathFreeObject(obj); xmlXPathFreeContext(ctx); xmlFreeDoc(doc); return 4; }
    }
    xmlChar **prefixes = calloc((size_t)argc, sizeof(xmlChar *));
    if (!prefixes) { xmlXPathFreeObject(obj); xmlXPathFreeContext(ctx); xmlFreeDoc(doc); return 2; }
    int n = 0;
    for (int i = 5; i < argc; i++) { if (strcmp(argv[i], "-") != 0) prefixes[n++] = (xmlChar *)argv[i]; }
    xmlChar *out = NULL;
    int len = xmlC14NDocDumpMemory(doc, obj ? obj->nodesetval : NULL, atoi(argv[2]), prefixes, atoi(argv[3]), &out);
    int status = len < 0 ? 5 : 0;
    if (len > 0 && fwrite(out, 1, (size_t)len, stdout) != (size_t)len) status = 6;
    xmlFree(out); free(prefixes); xmlXPathFreeObject(obj); xmlXPathFreeContext(ctx); xmlFreeDoc(doc);
    return status;
}
