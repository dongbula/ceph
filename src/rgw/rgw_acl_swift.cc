// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <string.h>

#include <list>

#include "rgw_common.h"
#include "rgw_user.h"
#include "rgw_acl_swift.h"

#define dout_subsys ceph_subsys_rgw

using namespace std;

#define SWIFT_PERM_READ  RGW_PERM_READ_OBJS
#define SWIFT_PERM_WRITE RGW_PERM_WRITE_OBJS

#define SWIFT_GROUP_ALL_USERS ".r:*"

static int parse_list(string& uid_list, list<string>& uids)
{
  char *s = strdup(uid_list.c_str());
  if (!s) {
    return -ENOMEM;
  }

  char *tokctx;
  const char *p = strtok_r(s, " ,", &tokctx);
  while (p) {
    if (*p) {
      string acl = p;
      uids.push_back(acl);
    }
    p = strtok_r(NULL, " ,", &tokctx);
  }
  free(s);
  return 0;
}

static bool uid_is_public(string& uid)
{
  if (uid[0] != '.' || uid[1] != 'r')
    return false;

  int pos = uid.find(':');
  if (pos < 0 || pos == (int)uid.size())
    return false;

  string sub = uid.substr(0, pos);
  string after = uid.substr(pos + 1);

  if (after.compare("*") != 0)
    return false;

  return sub.compare(".r") == 0 ||
         sub.compare(".ref") == 0 ||
         sub.compare(".referer") == 0 ||
         sub.compare(".referrer") == 0;
}

static bool extract_referer_urlspec(const string& uid, string& url_spec)
{
  const size_t pos = uid.find(':');
  if (string::npos == pos) {
    return false;
  }

  const auto sub = uid.substr(0, pos);
  url_spec = uid.substr(pos + 1);

  return sub.compare(".r") == 0 ||
         sub.compare(".referer") == 0 ||
         sub.compare(".referrer") == 0;
}

static bool normalize_referer_urlspec(string& url_spec, bool& is_negative)
{
  try {
    if ('-' == url_spec[0]) {
      is_negative = true;
      url_spec = url_spec.substr(1);
    } else {
      is_negative = false;
    }
    if (url_spec != "*" && '*' == url_spec[0]) {
      url_spec = url_spec.substr(1);
    }

    return !url_spec.empty() && url_spec != ".";
  } catch (std::out_of_range) {
    return false;
  }
}

 void RGWAccessControlPolicy_SWIFT::add_grants(RGWRados *store, list<string>& uids, int perm)
 {
   list<string>::iterator iter;
   for (iter = uids.begin(); iter != uids.end(); ++iter ) {
     ACLGrant grant;
     string& uid = *iter;
     string url_spec;

    if (uid_is_public(uid)) {
      grant.set_group(ACL_GROUP_ALL_USERS, perm);
      acl.add_grant(&grant);
    } else if (extract_referer_urlspec(uid, url_spec)) {
      if (0 != (perm & SWIFT_PERM_WRITE)) {
        ldout(cct, 10) << "cannot grant write access for referers" << dendl;
        continue;
      }

      bool is_negative = false;
      if (false == normalize_referer_urlspec(url_spec, is_negative)) {
        ldout(cct, 10) << "cannot normalize referer: " << url_spec << dendl;
        continue;
      } else {
        ldout(cct, 10) << "normalized referer to url_spec=" << url_spec
                       << ", is_negative=" << is_negative << dendl;
      }

      if (is_negative) {
        /* Forbid access. */
        grant.set_referer(url_spec, 0);
      } else {
        grant.set_referer(url_spec, perm);
      }

      acl.add_grant(&grant);
    } else {
      rgw_user user(uid);
      RGWUserInfo grant_user;

      if (rgw_get_user_info_by_uid(store, user, grant_user) < 0) {
        ldout(cct, 10) << "grant user does not exist: " << uid << dendl;
        /* skipping silently */
      } else {
        grant.set_canon(user, grant_user.display_name, perm);
        acl.add_grant(&grant);
      }
    }
  }
}

bool RGWAccessControlPolicy_SWIFT::create(RGWRados *store, rgw_user& id, string& name, string& read_list, string& write_list)
{
  acl.create_default(id, name);
  owner.set_id(id);
  owner.set_name(name);

  if (read_list.size()) {
    list<string> uids;
    int r = parse_list(read_list, uids);
    if (r < 0) {
      ldout(cct, 0) << "ERROR: parse_list returned r=" << r << dendl;
      return false;
    }

    add_grants(store, uids, SWIFT_PERM_READ);
  }
  if (write_list.size()) {
    list<string> uids;
    int r = parse_list(write_list, uids);
    if (r < 0) {
      ldout(cct, 0) << "ERROR: parse_list returned r=" << r << dendl;
      return false;
    }

    add_grants(store, uids, SWIFT_PERM_WRITE);
  }
  return true;
}

void RGWAccessControlPolicy_SWIFT::to_str(string& read, string& write)
{
  multimap<string, ACLGrant>& m = acl.get_grant_map();
  multimap<string, ACLGrant>::iterator iter;

  for (iter = m.begin(); iter != m.end(); ++iter) {
    ACLGrant& grant = iter->second;
    int perm = grant.get_permission().get_permissions();
    rgw_user id;
    string url_spec;
    if (!grant.get_id(id)) {
      if (grant.get_group() == ACL_GROUP_ALL_USERS) {
        id = SWIFT_GROUP_ALL_USERS;
      } else {
        url_spec = grant.get_referer();
        if (url_spec.empty()) {
          continue;
        }
        id = (perm != 0) ? ".r:" + url_spec : ".r:-" + url_spec;
      }
    }
    if (perm & SWIFT_PERM_READ) {
      if (!read.empty())
        read.append(", ");
      read.append(id.to_str());
    } else if (perm & SWIFT_PERM_WRITE) {
      if (!write.empty())
        write.append(", ");
      write.append(id.to_str());
    } else if (perm == 0 && !url_spec.empty()) {
      /* only X-Container-Read headers support referers */
      if (!read.empty()) {
        read.append(", ");
      }
      read.append(id.to_str());
    }
  }
}

