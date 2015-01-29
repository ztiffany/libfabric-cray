/*
 * Copyright (c) 2014 Los Alamos National Security, LLC. Allrights reserved.
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <gni_pub.h>
#include "gnix.h"
#include "fi.h"
#include "prov.h"

static int
gnix_getinfo(uint32_t version, const char *node, const char *service,
             uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
  // Do some verification of hints here

  int err = -FI_ENODATA;
  
  if (hints) {
    switch (hints->ep_type) {
    case FI_EP_RDM:
      return gnix_rdm_getinfo(version, node, service, flags, hints, info);
    case FI_EP_DGRAM:
      return err;
    case FI_EP_MSG:
      return err;
    default:
      break;
    }
  }

  // Chain together info from all supported endpoint types
  // Currently, we only support RDM
  err = gnix_rdm_getinfo(version, node, service, flags, hints, info);

  return err;
}

static int
gnix_fabric(struct fi_fabric_attr *attr,
            struct fid_fabric **fabric, void *context)
{
  return 0;
}

static void
gnix_fini(void)
{
  return;
}

struct fi_provider gnix_prov = {
  .name = "GNI",
  .version = FI_VERSION(GNI_MAJOR_VERSION, GNI_MINOR_VERSION), 
  .fi_version = FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION),
  .getinfo = gnix_getinfo,
  .fabric = gnix_fabric,
  .cleanup = gnix_fini
};

GNI_INI
{
  return (&gnix_prov);
}
