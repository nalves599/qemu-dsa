/*
 * Intel IOMMU acceleration with nested translation
 *
 * Copyright (C) 2026 Intel Corporation.
 *
 * Authors: Zhenzhong Duan <zhenzhong.duan@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/iommufd.h"
#include "system/kvm.h"
#include "intel_iommu_internal.h"
#include "intel_iommu_accel.h"
#include "hw/core/iommu.h"
#include "hw/pci/pci_bus.h"
#include "trace.h"

static bool vtd_kvm_pasid_translation(uint32_t flags, uint32_t guest_pasid,
                                      uint32_t host_pasid, Error **errp)
{
#ifdef CONFIG_KVM
    struct kvm_x86_pasid_translation cfg = {
        .flags = flags,
        .guest_pasid = guest_pasid,
        .host_pasid = host_pasid,
    };
    int ret;

    if (!kvm_enabled()) {
        return true;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_X86_PASID_TRANSLATION)) {
        error_setg(errp, "KVM does not support x86 PASID translation");
        return false;
    }

    ret = kvm_vm_ioctl(kvm_state, KVM_X86_SET_PASID_TRANSLATION, &cfg);
    if (ret) {
        error_setg_errno(errp, -ret,
                         "KVM PASID translation op %#x guest PASID %u host PASID %u failed",
                         flags, guest_pasid, host_pasid);
        return false;
    }
#endif
    return true;
}

typedef struct VTDPASIDTranslation {
    IntelIOMMUState *iommu_state;
    uint32_t guest_pasid;
    uint32_t host_pasid;
    uint32_t fs_hwpt_id;
    IOMMUFDBackend *host_pasid_iommufd;
    IOMMUFDBackend *fs_hwpt_iommufd;
    bool host_pasid_valid;
    bool fs_hwpt_valid;
    bool kvm_mapped;
    unsigned int users;
} VTDPASIDTranslation;

static GHashTable *vtd_pasid_translation_cache(IntelIOMMUState *s)
{
    if (!s->vtd_pasid_translation) {
        s->vtd_pasid_translation = g_hash_table_new_full(g_direct_hash,
                                                         g_direct_equal, NULL,
                                                         g_free);
    }

    return s->vtd_pasid_translation;
}

static VTDPASIDTranslation *
vtd_pasid_translation_lookup(IntelIOMMUState *s, uint32_t guest_pasid)
{
    return g_hash_table_lookup(vtd_pasid_translation_cache(s),
                               GUINT_TO_POINTER(guest_pasid));
}

static bool vtd_pasid_translation_host_in_use(IntelIOMMUState *s,
                                              uint32_t guest_pasid,
                                              uint32_t host_pasid)
{
    GHashTableIter iter;
    VTDPASIDTranslation *translation;

    g_hash_table_iter_init(&iter, vtd_pasid_translation_cache(s));
    while (g_hash_table_iter_next(&iter, NULL, (void **)&translation)) {
        if (translation->guest_pasid != guest_pasid &&
            translation->host_pasid_valid &&
            translation->host_pasid == host_pasid) {
            return true;
        }
    }

    return false;
}

static VTDPASIDTranslation *
vtd_pasid_translation_get_or_create(IntelIOMMUState *s, uint32_t guest_pasid)
{
    VTDPASIDTranslation *translation;

    translation = vtd_pasid_translation_lookup(s, guest_pasid);
    if (translation) {
        return translation;
    }

    translation = g_new0(VTDPASIDTranslation, 1);
    translation->iommu_state = s;
    translation->guest_pasid = guest_pasid;
    translation->host_pasid = UINT32_MAX;
    g_hash_table_insert(vtd_pasid_translation_cache(s),
                        GUINT_TO_POINTER(guest_pasid), translation);
    return translation;
}

static void vtd_pasid_translation_free_fs_hwpt(VTDPASIDTranslation *translation)
{
    IntelIOMMUState *s = translation->iommu_state;

    if (!translation->fs_hwpt_valid) {
        return;
    }

    if (s) {
        s->pasid_translation_nested_hwpt_frees++;
        trace_vtd_pasid_translation_nested_hwpt_free(
            translation->guest_pasid, translation->host_pasid,
            translation->fs_hwpt_id, translation->users,
            s->pasid_translation_nested_hwpt_frees);
    }
    warn_report("VT-d PASID translation free nested HWPT: guest PASID %u "
                "host PASID %u hwpt %u users=%u",
                translation->guest_pasid, translation->host_pasid,
                translation->fs_hwpt_id, translation->users);
    iommufd_backend_free_id(translation->fs_hwpt_iommufd,
                            translation->fs_hwpt_id);
    translation->fs_hwpt_id = 0;
    translation->fs_hwpt_iommufd = NULL;
    translation->fs_hwpt_valid = false;
}

static void vtd_pasid_translation_release_host_pasid(
    VTDPASIDTranslation *translation)
{
    IntelIOMMUState *s = translation->iommu_state;
    uint32_t host_pasid;

    if (!translation->host_pasid_valid || !translation->host_pasid_iommufd) {
        return;
    }

    host_pasid = translation->host_pasid;
    if (s) {
        s->pasid_translation_host_pasid_releases++;
        trace_vtd_pasid_translation_release_host_pasid(
            translation->guest_pasid, host_pasid, translation->users,
            s->pasid_translation_host_pasid_releases);
    }
    warn_report("VT-d PASID translation release host PASID: guest PASID %u "
                "host PASID %u users=%u",
                translation->guest_pasid, host_pasid, translation->users);
    iommufd_backend_host_pasid_release(translation->host_pasid_iommufd,
                                       host_pasid);
    translation->host_pasid = UINT32_MAX;
    translation->host_pasid_iommufd = NULL;
    translation->host_pasid_valid = false;
}

static bool vtd_pasid_translation_map_kvm(VTDPASIDTranslation *translation,
                                          Error **errp)
{
    IntelIOMMUState *s = translation->iommu_state;

    if (translation->kvm_mapped) {
        return true;
    }

    if (!translation->host_pasid_valid) {
        error_setg(errp, "guest PASID %u has no selected host PASID",
                   translation->guest_pasid);
        return false;
    }

    if (!vtd_kvm_pasid_translation(KVM_X86_PASID_TRANSLATION_MAP,
                                   translation->guest_pasid,
                                   translation->host_pasid, errp)) {
        return false;
    }

    translation->kvm_mapped = true;
    if (s) {
        s->pasid_translation_kvm_maps++;
        trace_vtd_pasid_translation_kvm_map(
            translation->guest_pasid, translation->host_pasid,
            s->pasid_translation_kvm_maps);
    }
    warn_report("VT-d PASID translation KVM map: guest PASID %u -> host PASID %u",
                translation->guest_pasid, translation->host_pasid);
    return true;
}

static bool vtd_pasid_translation_unmap_kvm(VTDPASIDTranslation *translation,
                                            Error **errp)
{
    IntelIOMMUState *s = translation->iommu_state;

    if (!translation->kvm_mapped) {
        return true;
    }

    if (!vtd_kvm_pasid_translation(KVM_X86_PASID_TRANSLATION_UNMAP,
                                   translation->guest_pasid, 0, errp)) {
        return false;
    }

    if (s) {
        s->pasid_translation_kvm_unmaps++;
        trace_vtd_pasid_translation_kvm_unmap(
            translation->guest_pasid, translation->host_pasid,
            s->pasid_translation_kvm_unmaps);
    }
    warn_report("VT-d PASID translation KVM unmap: guest PASID %u host PASID %u",
                translation->guest_pasid, translation->host_pasid);
    translation->kvm_mapped = false;
    return true;
}

static void vtd_pasid_translation_remove(IntelIOMMUState *s,
                                         VTDPASIDTranslation *translation)
{
    uint32_t guest_pasid = translation->guest_pasid;
    Error *local_err = NULL;

    if (!vtd_pasid_translation_unmap_kvm(translation, &local_err)) {
        error_reportf_err(local_err,
                          "Late KVM PASID translation cleanup failed: ");
    }
    vtd_pasid_translation_free_fs_hwpt(translation);
    vtd_pasid_translation_release_host_pasid(translation);
    g_hash_table_remove(vtd_pasid_translation_cache(s),
                        GUINT_TO_POINTER(guest_pasid));
}

static void vtd_pasid_translation_put(IntelIOMMUState *s, uint32_t guest_pasid,
                                      uint32_t host_pasid)
{
    VTDPASIDTranslation *translation;

    translation = vtd_pasid_translation_lookup(s, guest_pasid);
    if (!translation) {
        return;
    }

    if (translation->host_pasid_valid &&
        translation->host_pasid != host_pasid) {
        warn_report("VT-d PASID translation host PASID mismatch while "
                    "detaching guest PASID %u: cache=%u detached=%u",
                    guest_pasid, translation->host_pasid, host_pasid);
        return;
    }

    if (translation->users) {
        translation->users--;
    }

    if (!translation->users) {
        if (translation->kvm_mapped) {
            warn_report("VT-d PASID translation late final-user cleanup: "
                        "guest PASID %u host PASID %u",
                        guest_pasid, translation->host_pasid);
        }
        vtd_pasid_translation_remove(s, translation);
    }
}

static void vtd_pasid_translation_remove_if_unused(IntelIOMMUState *s,
                                                   VTDPASIDTranslation *translation)
{
    if (translation && !translation->users && !translation->kvm_mapped) {
        vtd_pasid_translation_free_fs_hwpt(translation);
        vtd_pasid_translation_release_host_pasid(translation);
        g_hash_table_remove(vtd_pasid_translation_cache(s),
                            GUINT_TO_POINTER(translation->guest_pasid));
    }
}

static void vtd_pasid_translation_cache_reset(IntelIOMMUState *s)
{
    GHashTableIter iter;
    VTDPASIDTranslation *translation;

    if (!s->vtd_pasid_translation) {
        return;
    }

    g_hash_table_iter_init(&iter, s->vtd_pasid_translation);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&translation)) {
        Error *local_err = NULL;

        if (!vtd_pasid_translation_unmap_kvm(translation, &local_err)) {
            error_reportf_err(local_err,
                              "Resetting KVM PASID translation cache failed: ");
        }
        vtd_pasid_translation_free_fs_hwpt(translation);
        vtd_pasid_translation_release_host_pasid(translation);
        g_hash_table_iter_remove(&iter);
    }
}

static int vtd_hiod_get_pe_from_pasid(VTDAccelPASIDCacheEntry *vtd_pce,
                                      VTDPASIDEntry *pe)
{
    VTDHostIOMMUDevice *vtd_hiod = vtd_pce->vtd_hiod;
    IntelIOMMUState *s = vtd_hiod->iommu_state;
    uint32_t pasid = vtd_pce->pasid;
    VTDContextEntry ce;
    int ret;

    if (!s->dmar_enabled || !s->root_scalable) {
        return -VTD_FR_RTADDR_INV_TTM;
    }

    ret = vtd_dev_to_context_entry(s, pci_bus_num(vtd_hiod->bus),
                                   vtd_hiod->devfn, &ce);
    if (ret) {
        return ret;
    }

    return vtd_ce_get_pasid_entry(s, &ce, pe, pasid);
}

bool vtd_check_hiod_accel(IntelIOMMUState *s, VTDHostIOMMUDevice *vtd_hiod,
                          Error **errp)
{
    HostIOMMUDevice *hiod = vtd_hiod->hiod;
    struct HostIOMMUDeviceCaps *caps = &hiod->caps;
    struct iommu_hw_info_vtd *vtd = &caps->vendor_caps.vtd;
    uint8_t hpasid = VTD_ECAP_GET_PSS(vtd->ecap_reg) + 1;
    PCIBus *bus = vtd_hiod->bus;
    PCIDevice *pdev = bus->devices[vtd_hiod->devfn];

    if (!object_dynamic_cast(OBJECT(hiod), TYPE_HOST_IOMMU_DEVICE_IOMMUFD)) {
        error_setg(errp, "Need IOMMUFD backend when x-flts=on");
        return false;
    }

    if (caps->type != IOMMU_HW_INFO_TYPE_INTEL_VTD) {
        error_setg(errp, "Incompatible host platform IOMMU type %d",
                   caps->type);
        return false;
    }

    if (s->fs1gp && !(vtd->cap_reg & VTD_CAP_FS1GP)) {
        error_setg(errp,
                   "First stage 1GB large page is unsupported by host IOMMU");
        return false;
    }

    /* Only do the check when host device support PASIDs */
    if (caps->max_pasid_log2 && s->pasid > hpasid) {
        error_setg(errp, "PASID bits size %d > host IOMMU PASID bits size %d",
                   s->pasid, hpasid);
        return false;
    }

    if (pci_device_get_iommu_bus_devfn(pdev, &bus, NULL, NULL)) {
        error_setg(errp, "Host device downstream to a PCI bridge is "
                   "unsupported when x-flts=on");
        return false;
    }

    return true;
}

VTDHostIOMMUDevice *vtd_find_hiod_iommufd(VTDAddressSpace *as)
{
    IntelIOMMUState *s = as->iommu_state;
    struct vtd_as_key key = {
        .bus = as->bus,
        .devfn = as->devfn,
    };
    VTDHostIOMMUDevice *vtd_hiod = g_hash_table_lookup(s->vtd_host_iommu_dev,
                                                       &key);

    if (vtd_hiod && vtd_hiod->hiod &&
        object_dynamic_cast(OBJECT(vtd_hiod->hiod),
                            TYPE_HOST_IOMMU_DEVICE_IOMMUFD)) {
        return vtd_hiod;
    }
    return NULL;
}

static bool vtd_create_fs_hwpt(VTDHostIOMMUDevice *vtd_hiod,
                               VTDPASIDEntry *pe, uint32_t *fs_hwpt_id,
                               Error **errp)
{
    HostIOMMUDeviceIOMMUFD *hiodi = HOST_IOMMU_DEVICE_IOMMUFD(vtd_hiod->hiod);
    struct iommu_hwpt_vtd_s1 vtd = {};
    uint32_t flags = vtd_hiod->iommu_state->pasid ? IOMMU_HWPT_ALLOC_PASID : 0;

    vtd.flags = (VTD_SM_PASID_ENTRY_SRE(pe) ? IOMMU_VTD_S1_SRE : 0) |
                (VTD_SM_PASID_ENTRY_WPE(pe) ? IOMMU_VTD_S1_WPE : 0) |
                (VTD_SM_PASID_ENTRY_EAFE(pe) ? IOMMU_VTD_S1_EAFE : 0);
    vtd.addr_width = vtd_pe_get_fs_aw(pe);
    vtd.pgtbl_addr = (uint64_t)vtd_pe_get_fspt_base(pe);

    return iommufd_backend_alloc_hwpt(hiodi->iommufd, hiodi->devid,
                                      hiodi->hwpt_id, flags,
                                      IOMMU_HWPT_DATA_VTD_S1, sizeof(vtd), &vtd,
                                      fs_hwpt_id, errp);
}

static void vtd_destroy_old_fs_hwpt(VTDAccelPASIDCacheEntry *vtd_pce)
{
    HostIOMMUDeviceIOMMUFD *hiodi =
        HOST_IOMMU_DEVICE_IOMMUFD(vtd_pce->vtd_hiod->hiod);
    IntelIOMMUState *s = vtd_pce->vtd_hiod->iommu_state;
    VTDPASIDTranslation *translation;

    if (!vtd_pce->fs_hwpt_id) {
        return;
    }

    translation = vtd_pasid_translation_lookup(s, vtd_pce->pasid);
    if (translation && translation->fs_hwpt_valid &&
        translation->fs_hwpt_id == vtd_pce->fs_hwpt_id) {
        vtd_pce->fs_hwpt_id = 0;
        return;
    }

    iommufd_backend_free_id(hiodi->iommufd, vtd_pce->fs_hwpt_id);
    vtd_pce->fs_hwpt_id = 0;
}

static bool vtd_device_attach_iommufd(VTDAccelPASIDCacheEntry *vtd_pce,
                                      Error **errp)
{
    VTDHostIOMMUDevice *vtd_hiod = vtd_pce->vtd_hiod;
    IntelIOMMUState *s = vtd_hiod->iommu_state;
    HostIOMMUDeviceIOMMUFD *hiodi = HOST_IOMMU_DEVICE_IOMMUFD(vtd_hiod->hiod);
    VTDPASIDEntry *pe = &vtd_pce->pasid_entry;
    uint32_t hwpt_id = hiodi->hwpt_id, guest_pasid = vtd_pce->pasid;
    uint32_t host_pasid = vtd_pce->host_pasid_valid ?
                          vtd_pce->host_pasid : UINT32_MAX;
    VTDPASIDTranslation *translation = NULL;
    Error *local_err = NULL;
    bool already_attached = vtd_pce->host_pasid_valid;
    bool attached = false;
    bool created_fs_hwpt = false;
    bool reused_fs_hwpt = false;
    bool ret;

    /*
     * We can get here only if flts=on, the supported PGTT is FST or PT.
     * Catch invalid PGTT when processing invalidation request to avoid
     * attaching to wrong hwpt.
     */
    if (!vtd_pe_pgtt_is_fst(pe) && !vtd_pe_pgtt_is_pt(pe)) {
        error_setg(errp, "Invalid PGTT type %d",
                   (uint8_t)VTD_SM_PASID_ENTRY_PGTT(pe));
        return false;
    }

    if (guest_pasid != IOMMU_NO_PASID) {
        translation = vtd_pasid_translation_get_or_create(s, guest_pasid);
        if (translation->host_pasid_valid) {
            if (translation->host_pasid_iommufd != hiodi->iommufd) {
                error_setg(errp,
                           "guest PASID %u is already translated on a different IOMMUFD backend",
                           guest_pasid);
                return false;
            }
            host_pasid = translation->host_pasid;
            s->pasid_translation_reuses++;
            trace_vtd_pasid_translation_reuse(
                guest_pasid, host_pasid, translation->users,
                s->pasid_translation_reuses);
            warn_report("VT-d PASID translation reuse: guest PASID %u -> "
                        "host PASID %u users=%u",
                        guest_pasid, host_pasid, translation->users);
        }
    }

    if (!vtd_kvm_pasid_translation(KVM_X86_PASID_TRANSLATION_ENABLE,
                                   0, 0, errp)) {
        return false;
    }

    if (vtd_pe_pgtt_is_fst(pe)) {
        if (translation && translation->fs_hwpt_valid) {
            hwpt_id = translation->fs_hwpt_id;
            reused_fs_hwpt = true;
            s->pasid_translation_nested_hwpt_reuses++;
            trace_vtd_pasid_translation_nested_hwpt_reuse(
                guest_pasid, host_pasid, hwpt_id, translation->users,
                s->pasid_translation_nested_hwpt_reuses);
            warn_report("VT-d PASID translation reuse nested HWPT: "
                        "guest PASID %u host PASID %u hwpt %u users=%u",
                        guest_pasid, host_pasid, hwpt_id,
                        translation->users);
        } else {
            if (!vtd_create_fs_hwpt(vtd_hiod, pe, &hwpt_id, errp)) {
                return false;
            }
            created_fs_hwpt = true;
        }
    }

    ret = host_iommu_device_iommufd_attach_guest_pasid_hwpt(
        hiodi, guest_pasid, hwpt_id, &host_pasid, errp);
    if (!ret) {
        goto err_free_hwpt;
    }
    attached = true;

    if (translation) {
        if (translation->host_pasid_valid &&
            translation->host_pasid != host_pasid) {
            error_setg(errp,
                       "guest PASID %u already maps to host PASID %u, but device selected %u",
                       guest_pasid, translation->host_pasid, host_pasid);
            goto err_detach;
        }

        if (!translation->host_pasid_valid) {
            if (vtd_pasid_translation_host_in_use(s, guest_pasid,
                                                  host_pasid)) {
                error_setg(errp,
                           "host PASID %u is already used by another guest PASID",
                           host_pasid);
                goto err_detach;
            }

            translation->host_pasid = host_pasid;
            translation->host_pasid_iommufd = hiodi->iommufd;
            translation->host_pasid_valid = true;
            s->pasid_translation_selects++;
            trace_vtd_pasid_translation_select(
                guest_pasid, host_pasid, s->pasid_translation_selects);
            warn_report("VT-d PASID translation select: guest PASID %u -> "
                        "host PASID %u",
                        guest_pasid, host_pasid);
        }

        if (created_fs_hwpt) {
            translation->fs_hwpt_id = hwpt_id;
            translation->fs_hwpt_iommufd = hiodi->iommufd;
            translation->fs_hwpt_valid = true;
            s->pasid_translation_nested_hwpt_allocs++;
            trace_vtd_pasid_translation_nested_hwpt_alloc(
                guest_pasid, host_pasid, hwpt_id,
                s->pasid_translation_nested_hwpt_allocs);
            warn_report("VT-d PASID translation select nested HWPT: "
                        "guest PASID %u host PASID %u hwpt %u",
                        guest_pasid, host_pasid, hwpt_id);
        }

        if (!vtd_pasid_translation_map_kvm(translation, errp)) {
            goto err_detach;
        }
    }

    trace_vtd_device_attach_hwpt(hiodi->devid, host_pasid, hwpt_id, ret);
    /* Destroy old fs_hwpt if it's a replacement */
    vtd_destroy_old_fs_hwpt(vtd_pce);
    vtd_pce->host_pasid = host_pasid;
    vtd_pce->host_pasid_valid = true;
    if (!already_attached && translation) {
        translation->users++;
    }
    if (translation) {
        s->pasid_translation_attaches++;
        trace_vtd_pasid_translation_attach(
            hiodi->devid, guest_pasid, host_pasid, hwpt_id,
            translation->users, already_attached, reused_fs_hwpt,
            s->pasid_translation_attaches);
        warn_report("VT-d PASID translation attach: dev_id %u guest PASID %u "
                    "host PASID %u hwpt %u users=%u%s%s",
                    hiodi->devid, guest_pasid, host_pasid, hwpt_id,
                    translation->users, already_attached ? " replacement" : "",
                    reused_fs_hwpt ? " shared-hwpt" : "");
    }
    if (vtd_pe_pgtt_is_fst(pe)) {
        vtd_pce->fs_hwpt_id = hwpt_id;
    }

    return true;

err_detach:
    if (attached &&
        !host_iommu_device_iommufd_detach_guest_pasid_hwpt(
            hiodi, guest_pasid, host_pasid, &local_err) &&
        local_err) {
        error_reportf_err(local_err,
                          "Detaching PASID after translation setup failure failed: ");
    }
err_free_hwpt:
    if (created_fs_hwpt && (!translation || !translation->fs_hwpt_valid ||
                            translation->fs_hwpt_id != hwpt_id)) {
        iommufd_backend_free_id(hiodi->iommufd, hwpt_id);
    } else if (created_fs_hwpt && translation && !translation->users &&
               !translation->kvm_mapped) {
        vtd_pasid_translation_free_fs_hwpt(translation);
    }
    vtd_pasid_translation_remove_if_unused(s, translation);
    return false;
}

static bool vtd_device_detach_iommufd(VTDAccelPASIDCacheEntry *vtd_pce,
                                      Error **errp)
{
    VTDHostIOMMUDevice *vtd_hiod = vtd_pce->vtd_hiod;
    HostIOMMUDeviceIOMMUFD *hiodi = HOST_IOMMU_DEVICE_IOMMUFD(vtd_hiod->hiod);

    IntelIOMMUState *s = vtd_hiod->iommu_state;
    uint32_t guest_pasid = vtd_pce->pasid;
    uint32_t host_pasid = vtd_pce->host_pasid_valid ?
                          vtd_pce->host_pasid : guest_pasid;
    VTDPASIDTranslation *translation = NULL;
    Error *local_err = NULL;
    unsigned int users_before_put = 0;
    bool kvm_pre_unmapped = false;
    bool ret;

    if (vtd_pce->host_pasid_valid && guest_pasid != IOMMU_NO_PASID) {
        translation = vtd_pasid_translation_lookup(s, guest_pasid);
        if (translation) {
            if (translation->host_pasid_valid &&
                translation->host_pasid != host_pasid) {
                error_setg(errp,
                           "guest PASID %u maps to host PASID %u, but detach has %u",
                           guest_pasid, translation->host_pasid, host_pasid);
                return false;
            }

            users_before_put = translation->users;
            if (translation->users <= 1 && translation->kvm_mapped) {
                warn_report("VT-d PASID translation final-user detach: "
                            "pre-unmapping KVM guest PASID %u host PASID %u "
                            "before dev_id %u detach",
                            guest_pasid, host_pasid, hiodi->devid);
                if (!vtd_pasid_translation_unmap_kvm(translation, errp)) {
                    return false;
                }
                kvm_pre_unmapped = true;
            }
        }
    }

    if (guest_pasid != IOMMU_NO_PASID || (s->dmar_enabled && s->root_scalable)) {
        ret = host_iommu_device_iommufd_detach_guest_pasid_hwpt(
            hiodi, guest_pasid, host_pasid, errp);
        trace_vtd_device_detach_hwpt(hiodi->devid, host_pasid, ret);
    } else {
        /*
         * If DMAR remapping is disabled or guest switches to legacy mode,
         * we fallback to the default HWPT which contains shadow page table.
         * So guest DMA could still work.
         */
        ret = host_iommu_device_iommufd_attach_hwpt(hiodi, IOMMU_NO_PASID,
                                                    hiodi->hwpt_id, errp);
        trace_vtd_device_reattach_def_hwpt(hiodi->devid, IOMMU_NO_PASID,
                                           hiodi->hwpt_id, ret);
    }

    if (!ret && kvm_pre_unmapped && translation) {
        if (!vtd_pasid_translation_map_kvm(translation, &local_err)) {
            error_reportf_err(local_err,
                              "Re-mapping KVM PASID translation after detach failure failed: ");
        }
    }

    if (ret) {
        vtd_destroy_old_fs_hwpt(vtd_pce);
        if (vtd_pce->host_pasid_valid) {
            s->pasid_translation_detaches++;
            trace_vtd_pasid_translation_detach(
                hiodi->devid, guest_pasid, host_pasid,
                users_before_put, users_before_put ? users_before_put - 1 : 0,
                s->pasid_translation_detaches);
            if (translation && users_before_put <= 1) {
                s->pasid_translation_final_detaches++;
                trace_vtd_pasid_translation_final_detach(
                    hiodi->devid, guest_pasid, host_pasid,
                    s->pasid_translation_final_detaches);
            }
            warn_report("VT-d PASID translation detach: dev_id %u guest PASID %u "
                        "host PASID %u users=%u->%u",
                        hiodi->devid, guest_pasid, host_pasid,
                        users_before_put,
                        users_before_put ? users_before_put - 1 : 0);
            vtd_pasid_translation_put(s, guest_pasid, host_pasid);
        }
        vtd_pce->host_pasid_valid = false;
    }

    return ret;
}

/*
 * This function is a loop function for the s->vtd_host_iommu_dev
 * and vtd_hiod->pasid_cache_list lists with VTDPIOTLBInvInfo as
 * execution filter. It propagates the piotlb invalidation to host.
 */
static void vtd_flush_host_piotlb_locked(VTDAccelPASIDCacheEntry *vtd_pce,
                                         VTDPIOTLBInvInfo *piotlb_info)
{
    VTDHostIOMMUDevice *vtd_hiod = vtd_pce->vtd_hiod;
    VTDPASIDEntry *pe = &vtd_pce->pasid_entry;
    uint16_t did;

    /* Nothing to do if there is no first stage HWPT attached */
    if (!vtd_pe_pgtt_is_fst(pe)) {
        return;
    }

    did = VTD_SM_PASID_ENTRY_DID(pe);

    if (piotlb_info->domain_id == did && piotlb_info->pasid == vtd_pce->pasid) {
        HostIOMMUDeviceIOMMUFD *hiodi =
            HOST_IOMMU_DEVICE_IOMMUFD(vtd_hiod->hiod);
        uint32_t entry_num = 1; /* Only implement one request for simplicity */
        Error *local_err = NULL;
        struct iommu_hwpt_vtd_s1_invalidate *cache = piotlb_info->inv_data;

        if (!iommufd_backend_invalidate_cache(hiodi->iommufd,
                                              vtd_pce->fs_hwpt_id,
                                              IOMMU_HWPT_INVALIDATE_DATA_VTD_S1,
                                              sizeof(*cache), &entry_num, cache,
                                              &local_err)) {
            /* Something wrong in kernel, but trying to continue */
            error_report_err(local_err);
        }
    }
}

void vtd_flush_host_piotlb_all_locked(IntelIOMMUState *s, uint16_t domain_id,
                                      uint32_t pasid, hwaddr addr,
                                      uint64_t npages, bool ih)
{
    struct iommu_hwpt_vtd_s1_invalidate cache_info = { 0 };
    VTDPIOTLBInvInfo piotlb_info;
    VTDHostIOMMUDevice *vtd_hiod;
    GHashTableIter hiod_it;

    cache_info.addr = addr;
    cache_info.npages = npages;
    cache_info.flags = ih ? IOMMU_VTD_INV_FLAGS_LEAF : 0;

    piotlb_info.domain_id = domain_id;
    piotlb_info.pasid = pasid;
    piotlb_info.inv_data = &cache_info;

    /*
     * Go through each vtd_pce in vtd_hiod->pasid_cache_list for each host
     * device, find out affected host device pasid which need host piotlb
     * invalidation. Piotlb invalidation should check pasid cache per
     * architecture point of view.
     */
    g_hash_table_iter_init(&hiod_it, s->vtd_host_iommu_dev);
    while (g_hash_table_iter_next(&hiod_it, NULL, (void **)&vtd_hiod)) {
        VTDAccelPASIDCacheEntry *vtd_pce;

        QLIST_FOREACH(vtd_pce, &vtd_hiod->pasid_cache_list, next) {
            vtd_flush_host_piotlb_locked(vtd_pce, &piotlb_info);
        }
    }
}

static bool vtd_accel_fill_pc(VTDHostIOMMUDevice *vtd_hiod, uint32_t pasid,
                              VTDPASIDEntry *pe)
{
    VTDAccelPASIDCacheEntry *vtd_pce;
    Error *local_err = NULL;

    QLIST_FOREACH(vtd_pce, &vtd_hiod->pasid_cache_list, next) {
        if (vtd_pce->pasid == pasid) {
            if (vtd_pasid_entry_compare(pe, &vtd_pce->pasid_entry)) {
                VTDPASIDEntry old_pe = vtd_pce->pasid_entry;

                vtd_pce->pasid_entry = *pe;

                if (!vtd_device_attach_iommufd(vtd_pce, &local_err)) {
                    vtd_pce->pasid_entry = old_pe;
                    error_reportf_err(local_err, "%s",
                                      "Replacing HWPT attachment failed: ");
                    return false;
                }
            }
            return true;
        }
    }

    vtd_pce = g_malloc0(sizeof(VTDAccelPASIDCacheEntry));
    vtd_pce->vtd_hiod = vtd_hiod;
    vtd_pce->pasid = pasid;
    vtd_pce->pasid_entry = *pe;
    QLIST_INSERT_HEAD(&vtd_hiod->pasid_cache_list, vtd_pce, next);

    if (!vtd_device_attach_iommufd(vtd_pce, &local_err)) {
        error_reportf_err(local_err, "%s", "Attaching to HWPT failed: ");
        QLIST_REMOVE(vtd_pce, next);
        g_free(vtd_pce);
        return false;
    }

    return true;
}

static void vtd_accel_delete_pc(VTDAccelPASIDCacheEntry *vtd_pce,
                                VTDPASIDCacheInfo *pc_info)
{
    Error *local_err = NULL;

    if (!vtd_device_detach_iommufd(vtd_pce, &local_err)) {
        error_reportf_err(local_err, "%s", "Detaching from HWPT failed: ");
    }

    QLIST_REMOVE(vtd_pce, next);
    g_free(vtd_pce);

    if (pc_info->type == VTD_INV_DESC_PASIDC_G_PASID_SI) {
        pc_info->accel_pce_deleted = true;
    }
}

static void
vtd_accel_pasid_cache_invalidate_one(VTDAccelPASIDCacheEntry *vtd_pce,
                                     VTDPASIDCacheInfo *pc_info)
{
    VTDPASIDEntry pe;
    uint16_t did;

    /*
     * VTD_INV_DESC_PASIDC_G_DSI and VTD_INV_DESC_PASIDC_G_PASID_SI require
     * DID check. If DID doesn't match the value in cache or memory, then
     * it's not a pasid entry we want to invalidate.
     */
    switch (pc_info->type) {
    case VTD_INV_DESC_PASIDC_G_PASID_SI:
        if (pc_info->pasid != vtd_pce->pasid) {
            return;
        }
        /* Fall through */
    case VTD_INV_DESC_PASIDC_G_DSI:
        did = VTD_SM_PASID_ENTRY_DID(&vtd_pce->pasid_entry);
        if (pc_info->did != did) {
            return;
        }
    }

    if (vtd_hiod_get_pe_from_pasid(vtd_pce, &pe)) {
        /*
         * No valid pasid entry in guest memory. e.g. pasid entry was modified
         * to be either all-zero or non-present. Either case means existing
         * pasid cache should be invalidated.
         */
        vtd_accel_delete_pc(vtd_pce, pc_info);
        return;
    }

    if (vtd_pasid_entry_compare(&pe, &vtd_pce->pasid_entry)) {
        IntelIOMMUState *s = vtd_pce->vtd_hiod->iommu_state;

        s->pasid_translation_stale_invalidations++;
        trace_vtd_pasid_translation_stale_invalidate(
            vtd_pce->pasid, s->pasid_translation_stale_invalidations);
        warn_report("VT-d PASID translation invalidate stale PASID cache: "
                    "guest PASID %u", vtd_pce->pasid);
        vtd_accel_delete_pc(vtd_pce, pc_info);
    }
}

static void vtd_accel_pasid_cache_invalidate(VTDHostIOMMUDevice *vtd_hiod,
                                             VTDPASIDCacheInfo *pc_info)
{
    VTDAccelPASIDCacheEntry *vtd_pce, *next;

    QLIST_FOREACH_SAFE(vtd_pce, &vtd_hiod->pasid_cache_list, next, next) {
        vtd_accel_pasid_cache_invalidate_one(vtd_pce, pc_info);
    }
}

static bool vtd_accel_lazy_skip_pasid(IntelIOMMUState *s, uint32_t pasid)
{
    VTDPASIDTranslation *translation;

    if (!s->pasid_translation_lazy || pasid == IOMMU_NO_PASID) {
        return false;
    }

    /*
     * After the first ENQCMD/S exit has established the VM-level translation,
     * do not suppress later replays.  Those replays may be the only chance to
     * attach the already-translated host PASID to another assigned device.
     */
    translation = vtd_pasid_translation_lookup(s, pasid);
    if (translation && translation->kvm_mapped) {
        return false;
    }

    return !s->pasid_translation_lazy_pasid ||
           s->pasid_translation_lazy_pasid == pasid;
}

/*
 * This function walks over PASID range within [start, end) in a single
 * PASID table for entries matching @info type/did, then create
 * VTDAccelPASIDCacheEntry if not exist yet.
 */
static void vtd_sm_pasid_table_walk_one(VTDHostIOMMUDevice *vtd_hiod,
                                        dma_addr_t pt_base,
                                        int start,
                                        int end,
                                        VTDPASIDCacheInfo *info)
{
    IntelIOMMUState *s = vtd_hiod->iommu_state;
    VTDPASIDEntry pe;
    int pasid;

    for (pasid = start; pasid < end; pasid++) {
        if (vtd_get_pe_in_pasid_leaf_table(s, pasid, pt_base, &pe) ||
            !vtd_pe_present(&pe)) {
            continue;
        }

        if ((info->type == VTD_INV_DESC_PASIDC_G_DSI ||
             info->type == VTD_INV_DESC_PASIDC_G_PASID_SI) &&
            (info->did != VTD_SM_PASID_ENTRY_DID(&pe))) {
            /*
             * VTD_PASID_CACHE_DOMSI and VTD_PASID_CACHE_PASIDSI
             * requires domain id check. If domain id check fail,
             * go to next pasid.
             */
            continue;
        }

        if (vtd_accel_lazy_skip_pasid(s, pasid)) {
            Error *local_err = NULL;

            if (!vtd_kvm_pasid_translation(KVM_X86_PASID_TRANSLATION_ENABLE,
                                           0, 0, &local_err)) {
                error_reportf_err(local_err,
                                  "Enabling KVM PASID translation for lazy replay skip failed: ");
            }
            trace_vtd_pasid_translation_replay_skip(pasid);
            if (s->pasid_translation_replay_skips < 16) {
                warn_report("VT-d lazy PASID translation: skipped replay for "
                            "guest PASID %u", pasid);
            }
            s->pasid_translation_replay_skips++;
            continue;
        }

        vtd_accel_fill_pc(vtd_hiod, pasid, &pe);
    }
}

static bool
vtd_accel_replay_single_pasid_bind_for_dev(VTDHostIOMMUDevice *vtd_hiod,
                                           uint32_t pasid)
{
    IntelIOMMUState *s = vtd_hiod->iommu_state;
    uint64_t dev_max_pasid = 1ULL << vtd_hiod->hiod->caps.max_pasid_log2;
    VTDContextEntry ce;
    VTDPASIDDirEntry pdire;
    VTDPASIDEntry pe;
    uint32_t ce_max_pasid;
    dma_addr_t pt_base;

    if (pasid == IOMMU_NO_PASID || pasid >= dev_max_pasid) {
        return false;
    }

    if (vtd_dev_to_context_entry(s, pci_bus_num(vtd_hiod->bus),
                                 vtd_hiod->devfn, &ce)) {
        return false;
    }

    ce_max_pasid = vtd_sm_ce_get_pdt_entry_num(&ce) *
                   VTD_PASID_TABLE_ENTRY_NUM;
    if (pasid >= ce_max_pasid) {
        return false;
    }

    if (vtd_get_pdire_from_pdir_table(VTD_CE_GET_PASID_DIR_TABLE(&ce),
                                      pasid, &pdire) ||
        !vtd_pdire_present(&pdire)) {
        return false;
    }

    pt_base = pdire.val & VTD_PASID_TABLE_BASE_ADDR_MASK;
    if (vtd_get_pe_in_pasid_leaf_table(s, pasid, pt_base, &pe) ||
        !vtd_pe_present(&pe)) {
        return false;
    }

    return vtd_accel_fill_pc(vtd_hiod, pasid, &pe);
}

/*
 * In VT-d scalable mode translation, PASID dir + PASID table is used.
 * This function aims at looping over a range of PASIDs in the given
 * two level table to identify the pasid config in guest.
 */
static void vtd_sm_pasid_table_walk(VTDHostIOMMUDevice *vtd_hiod,
                                    dma_addr_t pdt_base,
                                    int start, int end,
                                    VTDPASIDCacheInfo *info)
{
    VTDPASIDDirEntry pdire;
    int pasid = start;
    int pasid_next;
    dma_addr_t pt_base;

    while (pasid < end) {
        pasid_next = (pasid + VTD_PASID_TABLE_ENTRY_NUM) &
                     ~(VTD_PASID_TABLE_ENTRY_NUM - 1);
        pasid_next = pasid_next < end ? pasid_next : end;

        if (!vtd_get_pdire_from_pdir_table(pdt_base, pasid, &pdire)
            && vtd_pdire_present(&pdire)) {
            pt_base = pdire.val & VTD_PASID_TABLE_BASE_ADDR_MASK;
            vtd_sm_pasid_table_walk_one(vtd_hiod, pt_base, pasid, pasid_next,
                                        info);
        }
        pasid = pasid_next;
    }
}

static void vtd_accel_replay_pasid_bind_for_dev(VTDHostIOMMUDevice *vtd_hiod,
                                                int start, int end,
                                                VTDPASIDCacheInfo *pc_info)
{
    IntelIOMMUState *s = vtd_hiod->iommu_state;
    VTDContextEntry ce;
    int dev_max_pasid = 1 << vtd_hiod->hiod->caps.max_pasid_log2;

    /*
     * QEMU and the host iommufd/VFIO APIs reserve PASID 0 as IOMMU_NO_PASID.
     * Do not create accelerated host PASID attachments for the guest's RID
     * PASID entry; SVA/ENQCMD PASIDs are real non-zero PASID table entries.
     */
    if (start == IOMMU_NO_PASID) {
        start++;
        if (start >= end) {
            return;
        }
    }

    if (!vtd_dev_to_context_entry(s, pci_bus_num(vtd_hiod->bus),
                                  vtd_hiod->devfn, &ce)) {
        VTDPASIDCacheInfo walk_info = *pc_info;
        uint32_t ce_max_pasid = vtd_sm_ce_get_pdt_entry_num(&ce) *
                                VTD_PASID_TABLE_ENTRY_NUM;

        end = MIN(end, MIN(dev_max_pasid, ce_max_pasid));

        vtd_sm_pasid_table_walk(vtd_hiod, VTD_CE_GET_PASID_DIR_TABLE(&ce),
                                start, end, &walk_info);
    }
}

/*
 * This function replays the guest pasid bindings by walking the two level
 * guest PASID table. For each valid pasid entry, it creates an entry
 * VTDAccelPASIDCacheEntry dynamically if not exist yet. This entry holds
 * info specific to a pasid
 */
void vtd_accel_pasid_cache_sync(IntelIOMMUState *s, VTDPASIDCacheInfo *pc_info)
{
    int start = IOMMU_NO_PASID, end = 1 << s->pasid;
    VTDHostIOMMUDevice *vtd_hiod;
    GHashTableIter hiod_it;

    if (!s->fsts) {
        return;
    }

    /*
     * VTDPASIDCacheInfo honors PCI pasid but VTDAccelPASIDCacheEntry honors
     * iommu pasid
     */
    if (pc_info->pasid == PCI_NO_PASID) {
        pc_info->pasid = IOMMU_NO_PASID;
    }

    switch (pc_info->type) {
    case VTD_INV_DESC_PASIDC_G_PASID_SI:
        start = pc_info->pasid;
        end = pc_info->pasid + 1;
        /* fall through */
    case VTD_INV_DESC_PASIDC_G_DSI:
        /*
         * loop all assigned devices, do domain id check in
         * vtd_sm_pasid_table_walk_one() after get pasid entry.
         */
        break;
    case VTD_INV_DESC_PASIDC_G_GLOBAL:
        /* loop all assigned devices */
        break;
    default:
        g_assert_not_reached();
    }

    /*
     * Loop all the vtd_hiod instances to sync the "pasid cache" per the
     * guest pasid configuration.
     *
     * VTD translation callback never accesses vtd_hiod and its corresponding
     * cached pasid entry, so no iommu lock needed here.
     *
     * Do invalidation as a separate first phase.  A guest PASID can be shared
     * by multiple assigned devices; replaying one device before deleting the
     * other stale users would let the shared translation cache reuse the old
     * host PASID/nested HWPT.
     */
    g_hash_table_iter_init(&hiod_it, s->vtd_host_iommu_dev);
    while (g_hash_table_iter_next(&hiod_it, NULL, (void **)&vtd_hiod)) {
        if (!object_dynamic_cast(OBJECT(vtd_hiod->hiod),
                                 TYPE_HOST_IOMMU_DEVICE_IOMMUFD)) {
            continue;
        }

        vtd_accel_pasid_cache_invalidate(vtd_hiod, pc_info);
    }

    g_hash_table_iter_init(&hiod_it, s->vtd_host_iommu_dev);
    while (g_hash_table_iter_next(&hiod_it, NULL, (void **)&vtd_hiod)) {
        if (!object_dynamic_cast(OBJECT(vtd_hiod->hiod),
                                 TYPE_HOST_IOMMU_DEVICE_IOMMUFD)) {
            continue;
        }

        vtd_accel_replay_pasid_bind_for_dev(vtd_hiod, start, end, pc_info);
    }
}

bool vtd_accel_handle_pasid_translation_exit(uint32_t guest_pasid, Error **errp)
{
    X86IOMMUState *iommu = x86_iommu_get_default();
    IntelIOMMUState *s;
    VTDHostIOMMUDevice *vtd_hiod;
    GHashTableIter hiod_it;
    uint64_t max_pasid;
    bool handled = false;

    if (!iommu ||
        !object_dynamic_cast(OBJECT(iommu), TYPE_INTEL_IOMMU_DEVICE)) {
        error_setg(errp, "KVM PASID translation exit without Intel VT-d");
        return false;
    }

    s = INTEL_IOMMU_DEVICE(iommu);
    s->pasid_translation_exits++;
    trace_vtd_pasid_translation_exit(guest_pasid);
    warn_report("VT-d PASID translation exit: guest PASID %u "
                "(exits=%" PRIu64 " maps=%" PRIu64 " failures=%" PRIu64
                " replay_skips=%" PRIu64 ")",
                guest_pasid, s->pasid_translation_exits,
                s->pasid_translation_exit_maps,
                s->pasid_translation_exit_failures,
                s->pasid_translation_replay_skips);

    if (!s->dmar_enabled || !s->root_scalable || !s->fsts || !s->pasid) {
        s->pasid_translation_exit_failures++;
        error_setg(errp,
                   "KVM PASID translation exit before scalable first-stage VT-d is enabled");
        return false;
    }

    max_pasid = 1ULL << s->pasid;
    if (guest_pasid == IOMMU_NO_PASID || guest_pasid >= max_pasid) {
        s->pasid_translation_exit_failures++;
        error_setg(errp, "invalid guest PASID %u for KVM translation",
                   guest_pasid);
        return false;
    }

    g_hash_table_iter_init(&hiod_it, s->vtd_host_iommu_dev);
    while (g_hash_table_iter_next(&hiod_it, NULL, (void **)&vtd_hiod)) {
        if (!object_dynamic_cast(OBJECT(vtd_hiod->hiod),
                                 TYPE_HOST_IOMMU_DEVICE_IOMMUFD)) {
            continue;
        }

        handled |= vtd_accel_replay_single_pasid_bind_for_dev(vtd_hiod,
                                                              guest_pasid);
    }

    if (!handled) {
        s->pasid_translation_exit_failures++;
        error_setg(errp,
                   "no assigned IOMMUFD device has a valid PASID entry for guest PASID %u",
                   guest_pasid);
    } else {
        s->pasid_translation_exit_maps++;
        trace_vtd_pasid_translation_exit_map(guest_pasid, handled);
        warn_report("VT-d PASID translation exit mapped guest PASID %u "
                    "(exits=%" PRIu64 " maps=%" PRIu64 " failures=%" PRIu64
                    " replay_skips=%" PRIu64 ")",
                    guest_pasid, s->pasid_translation_exits,
                    s->pasid_translation_exit_maps,
                    s->pasid_translation_exit_failures,
                    s->pasid_translation_replay_skips);
    }

    return handled;
}

/* Fake a global pasid cache invalidation to remove all pasid cache entries */
void vtd_accel_pasid_cache_reset(IntelIOMMUState *s)
{
    VTDPASIDCacheInfo pc_info = { .type = VTD_INV_DESC_PASIDC_G_GLOBAL };
    VTDHostIOMMUDevice *vtd_hiod;
    GHashTableIter hiod_it;

    g_hash_table_iter_init(&hiod_it, s->vtd_host_iommu_dev);
    while (g_hash_table_iter_next(&hiod_it, NULL, (void **)&vtd_hiod)) {
        vtd_accel_pasid_cache_invalidate(vtd_hiod, &pc_info);
    }

    vtd_pasid_translation_cache_reset(s);
}

static uint64_t vtd_get_host_iommu_quirks(uint32_t type,
                                          void *caps, uint32_t size)
{
    struct iommu_hw_info_vtd *vtd = caps;
    uint64_t quirks = 0;

    if (type == IOMMU_HW_INFO_TYPE_INTEL_VTD &&
        sizeof(struct iommu_hw_info_vtd) <= size &&
        vtd->flags & IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17) {
        quirks |= HOST_IOMMU_QUIRK_NESTING_PARENT_BYPASS_RO;
    }

    return quirks;
}

void vtd_iommu_ops_update_accel(PCIIOMMUOps *ops)
{
    ops->get_host_iommu_quirks = vtd_get_host_iommu_quirks;
}
