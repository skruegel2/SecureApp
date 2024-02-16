#ifndef SECUREAPIFUNCTIONLIST_H /* MISRA appeasement */
#define SECUREAPIFUNCTIONLIST_H

SECFUNC(/* in_type */ uint16_t,                                         \
        /* in_len */  sizeof(uint16_t),                                 \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getNumberOfDeviceCertificates)

SECFUNC(/* in_type */ slot_number_of_device_certificate_args,           \
        /* in_len */  sizeof(slot_number_of_device_certificate_args),   \
        /* out_len */ sizeof(pd_slot_t),                                \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getSlotNumberOfDeviceCertificate)

SECFUNC(/* in_type */ get_x509_certificate_from_slot_in_args,           \
        /* in_len */  sizeof(get_x509_certificate_from_slot_in_args),   \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getX509CertificateFromSlot)

SECFUNC(/* in_type */ pd_slot_t,                                        \
        /* in_len */  sizeof(pd_slot_t),                                \
        /* out_len */ sizeof(pd_slot_t),                                \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getParentOfCertificate)

SECFUNC(/* in_type */ number_of_keys_args,                              \
        /* in_len */  sizeof(number_of_keys_args),                      \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getNumberOfKeys)

SECFUNC(/* in_type */ slot_number_of_key_args,                          \
        /* in_len */  sizeof(slot_number_of_key_args),                  \
        /* out_len */ sizeof(pd_slot_t),                                \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getSlotNumberOfKey)

SECFUNC(/* in_type */ slot_number_of_key_for_certificate_args,          \
        /* in_len */  sizeof(slot_number_of_key_for_certificate_args),  \
        /* out_len */ sizeof(pd_slot_t),                                \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getSlotNumberOfKeyForCertificate)

SECFUNC(/* in_type */ details_of_key_args,                              \
        /* in_len */  sizeof(details_of_key_args),                      \
        /* out_len */ sizeof(pd_slot_t),                                \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getDetailsOfKey)

SECFUNC(/* in_type */ sign_using_key_args,                              \
        /* in_len */  sizeof(sign_using_key_args),                      \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    signUsingKey)

SECFUNC(/* in_type */ verify_using_key_args,                            \
        /* in_len */  sizeof(verify_using_key_args),                    \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    verifyUsingKey)

SECFUNC(/* in_type */ generate_shared_secret_in_args,                   \
        /* in_len */  sizeof(generate_shared_secret_in_args),           \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    generateSharedSecret)

SECFUNC(/* in_type */ get_sbm_info_in_args,                             \
        /* in_len */  sizeof(get_sbm_info_in_args),                     \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    SBM_API_ATTR_OVERLAP,                             \
        /* func */    getSBMInformation)

SECFUNC(/* in_type */ get_update_info_in_args,                          \
        /* in_len */  sizeof(get_update_info_in_args),                  \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    getUpdateInfo)

SECFUNC(/* in_type */ get_app_info_in_args,                             \
        /* in_len */  sizeof(get_app_info_in_args),                     \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    getApplicationInfo)

SECFUNC(/* in_type */ get_update_slot_info_in_args,                     \
        /* in_len */  sizeof(get_update_slot_info_in_args),             \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    getUpdateSlotInfo)

SECFUNC(/* in_type */ uint8_t, /* Dummy type */                         \
        /* in_len */  0,                                                \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    checkUpdateSlot)

SECFUNC(/* in_type */ uint8_t, /* Dummy type */                         \
        /* in_len */  0,                                                \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    installUpdate)

SECFUNC(/* in_type */ update_slot_begin_write_in_args,                  \
        /* in_len */  sizeof(update_slot_begin_write_in_args),          \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    updateSlotBeginWrite)

SECFUNC(/* in_type */ uint8_t, /* Dummy type */                         \
        /* in_len */  0,                                                \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    updateSlotEndWrite)

SECFUNC(/* in_type */ update_slot_write_in_args,                        \
        /* in_len */  sizeof(update_slot_write_in_args),                \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    updateSlotWrite)

SECFUNC(/* in_type */ get_sbm_performance_in_args,                      \
        /* in_len */  sizeof(get_sbm_performance_in_args),              \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    getSBMPerformance)

SECFUNC(/* in_type */ set_active_update_slot_in_args,                   \
        /* in_len */  sizeof(set_active_update_slot_in_args),           \
        /* out_len */ sizeof(int8_t),                                   \
        /* attr */    0,                                                \
        /* func */    setActiveUpdateSlot)

#endif /* SECUREAPIFUNCTIONLIST_H */
