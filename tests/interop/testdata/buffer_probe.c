/*
 * Independent test adapter for xmlsec1's public decryption API. Project MIT
 * license applies. API design: XML Security Library, Aleksey Sanin and
 * contributors (MIT), https://github.com/lsh123/xmlsec. No upstream code copied.
 * Only generated, bounded, local harness documents are accepted by the caller.
 * Prints buffer size only, never plaintext or keys. This bypasses both XML
 * replacement and CLI output so an empty authenticated buffer is observable.
 */
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>
#include <xmlsec/keysmngr.h>

int main(int argc, char **argv) {
    xmlSecKeysMngrPtr manager = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecEncCtxPtr context = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr encrypted;
    xmlSecBufferPtr result;
    int status = 1;
    if(argc != 4 || (strcmp(argv[2], "rsa") && strcmp(argv[2], "aes"))) {
        fprintf(stderr, "Usage: buffer_probe document rsa|aes key\n");
        return 1;
    }
    xmlInitParser();
    if(xmlSecInit() < 0 || xmlSecCheckVersion() != 1 ||
       xmlSecCryptoAppInit(NULL) < 0 || xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Reference initialization failed\n");
        return 1;
    }
    manager = xmlSecKeysMngrCreate();
    if(manager == NULL || xmlSecCryptoAppDefaultKeysMngrInit(manager) < 0) goto done;
    key = !strcmp(argv[2], "aes") ? xmlSecKeyReadBinaryFile(xmlSecKeyDataAesId, argv[3]) :
        xmlSecCryptoAppKeyLoadEx(argv[3], xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(key == NULL || xmlSecCryptoAppDefaultKeysMngrAdoptKey(manager, key) < 0) goto done;
    key = NULL; /* manager owns the adopted key */
    doc = xmlReadFile(argv[1], NULL, XML_PARSE_NONET);
    if(doc == NULL) goto done;
    encrypted = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(encrypted == NULL) goto done;
    context = xmlSecEncCtxCreate(manager);
    if(context == NULL) goto done;
    /* Sole explicit key, matching the CLI oracle's --lax-key-search policy. */
    context->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
    result = xmlSecEncCtxDecryptToBuffer(context, encrypted);
    if(result == NULL) goto done;
    printf("{\"size\":%zu}\n", (size_t)xmlSecBufferGetSize(result));
    status = 0;
done:
    if(context != NULL) xmlSecEncCtxDestroy(context);
    if(doc != NULL) xmlFreeDoc(doc);
    if(key != NULL) xmlSecKeyDestroy(key);
    if(manager != NULL) xmlSecKeysMngrDestroy(manager);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
    if(status != 0) fprintf(stderr, "Reference buffer decryption failed\n");
    return status;
}
