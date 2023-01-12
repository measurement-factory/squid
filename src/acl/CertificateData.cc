/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/CertificateData.h"
#include "acl/Checklist.h"
#include "base/CharacterSet.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "wordlist.h"

ACLCertificateData::ACLCertificateData(Ssl::GETX509ATTRIBUTE *sslStrategy, const char *attrs, bool optionalAttr) : validAttributesStr(attrs), attributeIsOptional(optionalAttr), values (), sslAttributeCall (sslStrategy)
{
    if (attrs) {
        size_t current = 0;
        size_t next = std::string::npos;
        SBuf valid(attrs);
        do {
            next = valid.find('|', current);
            validAttributes.push_back(valid.substr( current, (next == std::string::npos ? std::string::npos : next - current)));
            current = next + 1;
        } while (next != std::string::npos);
    }
}

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

template<class T>
inline int
splaystrcmp (T&l, T&r)
{
    return strcmp ((char *)l,(char *)r);
}

bool
ACLCertificateData::match(X509 *cert)
{
    if (!cert)
        return 0;

    char const *value = sslAttributeCall(cert, attribute.c_str());
    debugs(28, 6, (attribute.isEmpty() ? attribute.c_str() : "value") << "=" << value);
    if (value == nullptr)
        return 0;

    return values.match(value);
}

SBufList
ACLCertificateData::dump() const
{
    SBufList sl;
    if (validAttributesStr)
        sl.push_back(attribute);

    sl.splice(sl.end(),values.dump());
    return sl;
}

void
ACLCertificateData::parse()
{
    if (validAttributesStr) {
        //char *newAttribute = ConfigParser::strtokFile();
        auto newAttribute = attribute;
        ConfigParser::SetAclKey(newAttribute, "SSL certificate attribute", attributeIsOptional);
        // TODO: handle a case when an the same-ACL attribute changes from optional to required (and vice versa)
        if (attributeIsOptional && newAttribute.isEmpty())
            return;

        // Handle the cases where we have optional -x type attributes
        if (attributeIsOptional && newAttribute[0] != '-') {
            // The read token is not an attribute/option, so add it to values list
            values.insert(newAttribute.c_str());
        } else {
            bool valid = false;
            for (const auto attr: validAttributes) {
                if (attr.cmp("*") == 0 || attr == newAttribute) {
                    valid = true;
                    break;
                }
            }

            if (!valid) {
                debugs(28, DBG_CRITICAL, "FATAL: Unknown option. Supported option(s) are: " << validAttributesStr);
                self_destruct();
                return;
            }

            if (newAttribute.cmp("DN") != 0) {
                int nid = OBJ_txt2nid(newAttribute.c_str());
                if (nid == 0) {
                    if(newAttribute.findFirstNotOf(CharacterSet::DIGIT, 0) == SBuf::npos) { // looks like a numerical OID
                        // create a new object based on this attribute

                        // NOTE: Not a [bad] leak: If the same attribute
                        // has been added before, the OBJ_txt2nid call
                        // would return a valid nid value.
                        // TODO: call OBJ_cleanup() on reconfigure?
                        nid = OBJ_create(newAttribute.c_str(), newAttribute.c_str(),  newAttribute.c_str());
                        debugs(28, 7, "New SSL certificate attribute created with name: " << newAttribute << " and nid: " << nid);
                    }
                }
                if (nid == 0) {
                    debugs(28, DBG_CRITICAL, "FATAL: Not valid SSL certificate attribute name or numerical OID: " << newAttribute);
                    self_destruct();
                    return;
                }
            }
            attribute = newAttribute;
        }
    }

    values.parse();
}

bool
ACLCertificateData::empty() const
{
    return values.empty();
}

