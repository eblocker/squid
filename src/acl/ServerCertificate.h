/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SERVERCERTIFICATE_H
#define SQUID_SRC_ACL_SERVERCERTIFICATE_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLServerCertificateStrategy : public ACLStrategy<X509 *>
{
public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_SERVERCERTIFICATE_H */

