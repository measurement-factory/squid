#include "squid.h"
#include "acl/AdaptationServiceData.h"
#include "acl/Checklist.h"
#include "adaptation/Config.h"
#include "adaptation/ecap/Config.h"
#include "adaptation/icap/Config.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "wordlist.h"

void
ACLAdaptationServiceData::parse()
{
    Adaptation::Config::needHistory = true;
    while (char *t = ConfigParser::strtokFile()) {
        if (
#if USE_ECAP
            Adaptation::Ecap::TheConfig.findServiceConfig(t) == NULL &&
#endif
#if ICAP_CLIENT
            Adaptation::Icap::TheConfig.findServiceConfig(t) == NULL &&
#endif
            Adaptation::FindGroup(t) == NULL) {
            debugs(28, 0, "Adaptation service/group " << t << " in adaptation_service acl is not defined");
            self_destruct();
        }
        insert(t);
    }
}

ACLData<char const *> *
ACLAdaptationServiceData::clone() const
{
    return new ACLAdaptationServiceData(*this);
}

