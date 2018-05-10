LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := openssl
LOCAL_C_INCLUDES := \
  app/src/openssl \
  app/src/openssl/include \
  app/src/openssl/crypto \
  app/src/openssl/crypto/asn1 \
  app/src/openssl/crypto/evp \
  app/src/openssl/crypto/modes
LOCAL_SRC_FILES := \
  src/openssl/crypto/cryptlib.c \
  src/openssl/crypto/ex_data.c \
  src/openssl/crypto/mem.c \
  src/openssl/crypto/mem_clr.c \
  src/openssl/crypto/mem_dbg.c \
  src/openssl/crypto/o_init.c \
  src/openssl/crypto/o_time.c \
  src/openssl/crypto/aes/aes_cbc.c \
  src/openssl/crypto/aes/aes_core.c \
  src/openssl/crypto/aes/aes_ecb.c \
  src/openssl/crypto/aes/aes_misc.c \
  src/openssl/crypto/aes/aes_wrap.c \
  src/openssl/crypto/asn1/a_bitstr.c \
  src/openssl/crypto/asn1/a_bool.c \
  src/openssl/crypto/asn1/a_bytes.c \
  src/openssl/crypto/asn1/a_d2i_fp.c \
  src/openssl/crypto/asn1/a_digest.c \
  src/openssl/crypto/asn1/a_dup.c \
  src/openssl/crypto/asn1/a_enum.c \
  src/openssl/crypto/asn1/a_gentm.c \
  src/openssl/crypto/asn1/a_i2d_fp.c \
  src/openssl/crypto/asn1/a_int.c \
  src/openssl/crypto/asn1/a_mbstr.c \
  src/openssl/crypto/asn1/a_object.c \
  src/openssl/crypto/asn1/a_octet.c \
  src/openssl/crypto/asn1/a_print.c \
  src/openssl/crypto/asn1/a_set.c \
  src/openssl/crypto/asn1/a_sign.c \
  src/openssl/crypto/asn1/a_strex.c \
  src/openssl/crypto/asn1/a_strnid.c \
  src/openssl/crypto/asn1/a_time.c \
  src/openssl/crypto/asn1/a_type.c \
  src/openssl/crypto/asn1/a_utctm.c \
  src/openssl/crypto/asn1/a_utf8.c \
  src/openssl/crypto/asn1/a_verify.c \
  src/openssl/crypto/asn1/ameth_lib.c \
  src/openssl/crypto/asn1/asn1_err.c \
  src/openssl/crypto/asn1/asn1_gen.c \
  src/openssl/crypto/asn1/asn1_lib.c \
  src/openssl/crypto/asn1/asn1_par.c \
  src/openssl/crypto/asn1/asn_mime.c \
  src/openssl/crypto/asn1/asn_moid.c \
  src/openssl/crypto/asn1/asn_pack.c \
  src/openssl/crypto/asn1/bio_asn1.c \
  src/openssl/crypto/asn1/bio_ndef.c \
  src/openssl/crypto/asn1/d2i_pr.c \
  src/openssl/crypto/asn1/d2i_pu.c \
  src/openssl/crypto/asn1/evp_asn1.c \
  src/openssl/crypto/asn1/f_enum.c \
  src/openssl/crypto/asn1/f_int.c \
  src/openssl/crypto/asn1/f_string.c \
  src/openssl/crypto/asn1/i2d_pr.c \
  src/openssl/crypto/asn1/i2d_pu.c \
  src/openssl/crypto/asn1/n_pkey.c \
  src/openssl/crypto/asn1/nsseq.c \
  src/openssl/crypto/asn1/p5_pbe.c \
  src/openssl/crypto/asn1/p5_pbev2.c \
  src/openssl/crypto/asn1/p8_pkey.c \
  src/openssl/crypto/asn1/t_bitst.c \
  src/openssl/crypto/asn1/t_crl.c \
  src/openssl/crypto/asn1/t_pkey.c \
  src/openssl/crypto/asn1/t_req.c \
  src/openssl/crypto/asn1/t_spki.c \
  src/openssl/crypto/asn1/t_x509.c \
  src/openssl/crypto/asn1/t_x509a.c \
  src/openssl/crypto/asn1/tasn_dec.c \
  src/openssl/crypto/asn1/tasn_enc.c \
  src/openssl/crypto/asn1/tasn_fre.c \
  src/openssl/crypto/asn1/tasn_new.c \
  src/openssl/crypto/asn1/tasn_prn.c \
  src/openssl/crypto/asn1/tasn_typ.c \
  src/openssl/crypto/asn1/tasn_utl.c \
  src/openssl/crypto/asn1/x_algor.c \
  src/openssl/crypto/asn1/x_attrib.c \
  src/openssl/crypto/asn1/x_bignum.c \
  src/openssl/crypto/asn1/x_crl.c \
  src/openssl/crypto/asn1/x_exten.c \
  src/openssl/crypto/asn1/x_info.c \
  src/openssl/crypto/asn1/x_long.c \
  src/openssl/crypto/asn1/x_name.c \
  src/openssl/crypto/asn1/x_nx509.c \
  src/openssl/crypto/asn1/x_pkey.c \
  src/openssl/crypto/asn1/x_pubkey.c \
  src/openssl/crypto/asn1/x_req.c \
  src/openssl/crypto/asn1/x_sig.c \
  src/openssl/crypto/asn1/x_spki.c \
  src/openssl/crypto/asn1/x_val.c \
  src/openssl/crypto/asn1/x_x509.c \
  src/openssl/crypto/asn1/x_x509a.c \
  src/openssl/crypto/bio/b_dump.c \
  src/openssl/crypto/bio/b_print.c \
  src/openssl/crypto/bio/bf_buff.c \
  src/openssl/crypto/bio/bio_lib.c \
  src/openssl/crypto/bio/bss_file.c \
  src/openssl/crypto/bio/bss_mem.c \
  src/openssl/crypto/bio/bss_null.c \
  src/openssl/crypto/buffer/buffer.c \
  src/openssl/crypto/buffer/buf_str.c \
  src/openssl/crypto/bn/bn_add.c \
  src/openssl/crypto/bn/bn_asm.c \
  src/openssl/crypto/bn/bn_blind.c \
  src/openssl/crypto/bn/bn_ctx.c \
  src/openssl/crypto/bn/bn_div.c \
  src/openssl/crypto/bn/bn_exp.c \
  src/openssl/crypto/bn/bn_exp2.c \
  src/openssl/crypto/bn/bn_gcd.c \
  src/openssl/crypto/bn/bn_gf2m.c \
  src/openssl/crypto/bn/bn_kron.c \
  src/openssl/crypto/bn/bn_lib.c \
  src/openssl/crypto/bn/bn_mod.c \
  src/openssl/crypto/bn/bn_mont.c \
  src/openssl/crypto/bn/bn_mul.c \
  src/openssl/crypto/bn/bn_nist.c \
  src/openssl/crypto/bn/bn_prime.c \
  src/openssl/crypto/bn/bn_print.c \
  src/openssl/crypto/bn/bn_rand.c \
  src/openssl/crypto/bn/bn_recp.c \
  src/openssl/crypto/bn/bn_shift.c \
  src/openssl/crypto/bn/bn_sqr.c \
  src/openssl/crypto/bn/bn_sqrt.c \
  src/openssl/crypto/bn/bn_word.c \
  src/openssl/crypto/cmac/cm_ameth.c \
  src/openssl/crypto/cmac/cm_pmeth.c \
  src/openssl/crypto/cmac/cmac.c \
  src/openssl/crypto/cms/cms_asn1.c \
  src/openssl/crypto/cms/cms_att.c \
  src/openssl/crypto/cms/cms_cd.c \
  src/openssl/crypto/cms/cms_dd.c \
  src/openssl/crypto/cms/cms_enc.c \
  src/openssl/crypto/cms/cms_env.c \
  src/openssl/crypto/cms/cms_err.c \
  src/openssl/crypto/cms/cms_ess.c \
  src/openssl/crypto/cms/cms_io.c \
  src/openssl/crypto/cms/cms_kari.c \
  src/openssl/crypto/cms/cms_lib.c \
  src/openssl/crypto/cms/cms_pwri.c \
  src/openssl/crypto/cms/cms_sd.c \
  src/openssl/crypto/conf/conf_api.c \
  src/openssl/crypto/conf/conf_def.c \
  src/openssl/crypto/conf/conf_err.c \
  src/openssl/crypto/conf/conf_lib.c \
  src/openssl/crypto/conf/conf_mall.c \
  src/openssl/crypto/conf/conf_mod.c \
  src/openssl/crypto/conf/conf_sap.c \
  src/openssl/crypto/des/cfb64ede.c \
  src/openssl/crypto/des/des_enc.c \
  src/openssl/crypto/des/ecb3_enc.c \
  src/openssl/crypto/des/ofb64ede.c \
  src/openssl/crypto/des/set_key.c \
  src/openssl/crypto/dh/dh_asn1.c \
  src/openssl/crypto/dh/dh_ameth.c \
  src/openssl/crypto/dh/dh_check.c \
  src/openssl/crypto/dh/dh_gen.c \
  src/openssl/crypto/dh/dh_kdf.c \
  src/openssl/crypto/dh/dh_key.c \
  src/openssl/crypto/dh/dh_lib.c \
  src/openssl/crypto/dh/dh_pmeth.c \
  src/openssl/crypto/dh/dh_rfc5114.c \
  src/openssl/crypto/dsa/dsa_ameth.c \
  src/openssl/crypto/dsa/dsa_asn1.c \
  src/openssl/crypto/dsa/dsa_gen.c \
  src/openssl/crypto/dsa/dsa_key.c \
  src/openssl/crypto/dsa/dsa_lib.c \
  src/openssl/crypto/dsa/dsa_ossl.c \
  src/openssl/crypto/dsa/dsa_pmeth.c \
  src/openssl/crypto/dsa/dsa_sign.c \
  src/openssl/crypto/dsa/dsa_vrf.c \
  src/openssl/crypto/dso/dso_err.c \
  src/openssl/crypto/dso/dso_lib.c \
  src/openssl/crypto/dso/dso_null.c \
  src/openssl/crypto/dso/dso_openssl.c \
  src/openssl/crypto/ec/ec_ameth.c \
  src/openssl/crypto/ec/ec_asn1.c \
  src/openssl/crypto/ec/ec_curve.c \
  src/openssl/crypto/ec/ec_cvt.c \
  src/openssl/crypto/ec/ec_key.c \
  src/openssl/crypto/ec/ec_lib.c \
  src/openssl/crypto/ec/ec_mult.c \
  src/openssl/crypto/ec/ec_oct.c \
  src/openssl/crypto/ec/ec_pmeth.c \
  src/openssl/crypto/ec/ec_print.c \
  src/openssl/crypto/ec/ec2_mult.c \
  src/openssl/crypto/ec/ec2_oct.c \
  src/openssl/crypto/ec/ec2_smpl.c \
  src/openssl/crypto/ec/eck_prn.c \
  src/openssl/crypto/ec/ecp_mont.c \
  src/openssl/crypto/ec/ecp_nist.c \
  src/openssl/crypto/ec/ecp_oct.c \
  src/openssl/crypto/ec/ecp_smpl.c \
  src/openssl/crypto/ecdh/ech_err.c \
  src/openssl/crypto/ecdh/ech_key.c \
  src/openssl/crypto/ecdh/ech_kdf.c \
  src/openssl/crypto/ecdh/ech_lib.c \
  src/openssl/crypto/ecdh/ech_ossl.c \
  src/openssl/crypto/ecdsa/ecs_asn1.c \
  src/openssl/crypto/ecdsa/ecs_lib.c \
  src/openssl/crypto/ecdsa/ecs_ossl.c \
  src/openssl/crypto/ecdsa/ecs_sign.c \
  src/openssl/crypto/ecdsa/ecs_vrf.c \
  src/openssl/crypto/err/err.c \
  src/openssl/crypto/err/err_prn.c \
  src/openssl/crypto/evp/bio_md.c \
  src/openssl/crypto/evp/digest.c \
  src/openssl/crypto/evp/e_aes.c \
  src/openssl/crypto/evp/e_rc4.c \
  src/openssl/crypto/evp/bio_b64.c \
  src/openssl/crypto/evp/bio_enc.c \
  src/openssl/crypto/evp/e_des3.c \
  src/openssl/crypto/evp/encode.c \
  src/openssl/crypto/evp/evp_cnf.c \
  src/openssl/crypto/evp/evp_enc.c \
  src/openssl/crypto/evp/evp_err.c \
  src/openssl/crypto/evp/evp_key.c \
  src/openssl/crypto/evp/evp_lib.c \
  src/openssl/crypto/evp/evp_pbe.c \
  src/openssl/crypto/evp/evp_pkey.c \
  src/openssl/crypto/evp/m_md5.c \
  src/openssl/crypto/evp/m_sha1.c \
  src/openssl/crypto/evp/m_sigver.c \
  src/openssl/crypto/evp/names.c \
  src/openssl/crypto/evp/p_enc.c \
  src/openssl/crypto/evp/p_lib.c \
  src/openssl/crypto/evp/p_seal.c \
  src/openssl/crypto/evp/p_sign.c \
  src/openssl/crypto/evp/p_verify.c \
  src/openssl/crypto/evp/p5_crpt.c \
  src/openssl/crypto/evp/p5_crpt2.c \
  src/openssl/crypto/evp/pmeth_fn.c \
  src/openssl/crypto/evp/pmeth_gn.c \
  src/openssl/crypto/evp/pmeth_lib.c \
  src/openssl/crypto/hmac/hm_ameth.c \
  src/openssl/crypto/hmac/hm_pmeth.c \
  src/openssl/crypto/hmac/hmac.c \
  src/openssl/crypto/lhash/lhash.c \
  src/openssl/crypto/md5/md5_dgst.c \
  src/openssl/crypto/modes/cbc128.c \
  src/openssl/crypto/modes/ccm128.c \
  src/openssl/crypto/modes/cfb128.c \
  src/openssl/crypto/modes/ctr128.c \
  src/openssl/crypto/modes/gcm128.c \
  src/openssl/crypto/modes/ofb128.c \
  src/openssl/crypto/modes/wrap128.c \
  src/openssl/crypto/modes/xts128.c \
  src/openssl/crypto/objects/o_names.c \
  src/openssl/crypto/objects/obj_dat.c \
  src/openssl/crypto/objects/obj_lib.c \
  src/openssl/crypto/objects/obj_xref.c \
  src/openssl/crypto/ocsp/ocsp_asn.c \
  src/openssl/crypto/ocsp/ocsp_cl.c \
  src/openssl/crypto/ocsp/ocsp_err.c \
  src/openssl/crypto/ocsp/ocsp_ext.c \
  src/openssl/crypto/ocsp/ocsp_ht.c \
  src/openssl/crypto/ocsp/ocsp_lib.c \
  src/openssl/crypto/ocsp/ocsp_prn.c \
  src/openssl/crypto/ocsp/ocsp_srv.c \
  src/openssl/crypto/ocsp/ocsp_vfy.c \
  src/openssl/crypto/pem/pem_all.c \
  src/openssl/crypto/pem/pem_err.c \
  src/openssl/crypto/pem/pem_info.c \
  src/openssl/crypto/pem/pem_lib.c \
  src/openssl/crypto/pem/pem_oth.c \
  src/openssl/crypto/pem/pem_pk8.c \
  src/openssl/crypto/pem/pem_pkey.c \
  src/openssl/crypto/pem/pem_seal.c \
  src/openssl/crypto/pem/pem_sign.c \
  src/openssl/crypto/pem/pem_x509.c \
  src/openssl/crypto/pem/pem_xaux.c \
  src/openssl/crypto/pkcs12/p12_add.c \
  src/openssl/crypto/pkcs12/p12_asn.c \
  src/openssl/crypto/pkcs12/p12_attr.c \
  src/openssl/crypto/pkcs12/p12_crpt.c \
  src/openssl/crypto/pkcs12/p12_crt.c \
  src/openssl/crypto/pkcs12/p12_decr.c \
  src/openssl/crypto/pkcs12/p12_init.c \
  src/openssl/crypto/pkcs12/p12_key.c \
  src/openssl/crypto/pkcs12/p12_kiss.c \
  src/openssl/crypto/pkcs12/p12_mutl.c \
  src/openssl/crypto/pkcs12/p12_npas.c \
  src/openssl/crypto/pkcs12/p12_p8d.c \
  src/openssl/crypto/pkcs12/p12_p8e.c \
  src/openssl/crypto/pkcs12/p12_utl.c \
  src/openssl/crypto/pkcs12/pk12err.c \
  src/openssl/crypto/pkcs7/pk7_asn1.c \
  src/openssl/crypto/pkcs7/pk7_attr.c \
  src/openssl/crypto/pkcs7/pk7_doit.c \
  src/openssl/crypto/pkcs7/pk7_lib.c \
  src/openssl/crypto/pkcs7/pk7_mime.c \
  src/openssl/crypto/pkcs7/pk7_smime.c \
  src/openssl/crypto/pkcs7/pkcs7err.c \
  src/openssl/crypto/sha/sha1_one.c \
  src/openssl/crypto/sha/sha1dgst.c \
  src/openssl/crypto/sha/sha256.c \
  src/openssl/crypto/sha/sha512.c \
  src/openssl/crypto/rand/md_rand.c \
  src/openssl/crypto/rand/rand_egd.c \
  src/openssl/crypto/rand/rand_lib.c \
  src/openssl/crypto/rand/rand_unix.c \
  src/openssl/crypto/rc4/rc4_enc.c \
  src/openssl/crypto/rc4/rc4_skey.c \
  src/openssl/crypto/rc4/rc4_utl.c \
  src/openssl/crypto/rsa/rsa_ameth.c \
  src/openssl/crypto/rsa/rsa_asn1.c \
  src/openssl/crypto/rsa/rsa_crpt.c \
  src/openssl/crypto/rsa/rsa_eay.c \
  src/openssl/crypto/rsa/rsa_gen.c \
  src/openssl/crypto/rsa/rsa_lib.c \
  src/openssl/crypto/rsa/rsa_none.c \
  src/openssl/crypto/rsa/rsa_oaep.c \
  src/openssl/crypto/rsa/rsa_pk1.c \
  src/openssl/crypto/rsa/rsa_pmeth.c \
  src/openssl/crypto/rsa/rsa_pss.c \
  src/openssl/crypto/rsa/rsa_saos.c \
  src/openssl/crypto/rsa/rsa_sign.c \
  src/openssl/crypto/rsa/rsa_ssl.c \
  src/openssl/crypto/rsa/rsa_x931.c \
  src/openssl/crypto/stack/stack.c \
  src/openssl/crypto/ui/ui_err.c \
  src/openssl/crypto/ui/ui_lib.c \
  src/openssl/crypto/ui/ui_openssl.c \
  src/openssl/crypto/x509/by_dir.c \
  src/openssl/crypto/x509/by_file.c \
  src/openssl/crypto/x509/x509_att.c \
  src/openssl/crypto/x509/x509_cmp.c \
  src/openssl/crypto/x509/x509_d2.c \
  src/openssl/crypto/x509/x509_def.c \
  src/openssl/crypto/x509/x509_err.c \
  src/openssl/crypto/x509/x509_ext.c \
  src/openssl/crypto/x509/x509_lu.c \
  src/openssl/crypto/x509/x509_obj.c \
  src/openssl/crypto/x509/x509_r2x.c \
  src/openssl/crypto/x509/x509_req.c \
  src/openssl/crypto/x509/x509_set.c \
  src/openssl/crypto/x509/x509_trs.c \
  src/openssl/crypto/x509/x509_txt.c \
  src/openssl/crypto/x509/x509_v3.c \
  src/openssl/crypto/x509/x509_vfy.c \
  src/openssl/crypto/x509/x509_vpm.c \
  src/openssl/crypto/x509/x509cset.c \
  src/openssl/crypto/x509/x509name.c \
  src/openssl/crypto/x509/x509rset.c \
  src/openssl/crypto/x509/x509spki.c \
  src/openssl/crypto/x509/x509type.c \
  src/openssl/crypto/x509/x_all.c \
  src/openssl/crypto/x509v3/pcy_cache.c \
  src/openssl/crypto/x509v3/pcy_data.c \
  src/openssl/crypto/x509v3/pcy_lib.c \
  src/openssl/crypto/x509v3/pcy_map.c \
  src/openssl/crypto/x509v3/pcy_node.c \
  src/openssl/crypto/x509v3/pcy_tree.c \
  src/openssl/crypto/x509v3/v3_akey.c \
  src/openssl/crypto/x509v3/v3_akeya.c \
  src/openssl/crypto/x509v3/v3_alt.c \
  src/openssl/crypto/x509v3/v3_bcons.c \
  src/openssl/crypto/x509v3/v3_bitst.c \
  src/openssl/crypto/x509v3/v3_conf.c \
  src/openssl/crypto/x509v3/v3_cpols.c \
  src/openssl/crypto/x509v3/v3_crld.c \
  src/openssl/crypto/x509v3/v3_enum.c \
  src/openssl/crypto/x509v3/v3_extku.c \
  src/openssl/crypto/x509v3/v3_genn.c \
  src/openssl/crypto/x509v3/v3_ia5.c \
  src/openssl/crypto/x509v3/v3_info.c \
  src/openssl/crypto/x509v3/v3_int.c \
  src/openssl/crypto/x509v3/v3_lib.c \
  src/openssl/crypto/x509v3/v3_ncons.c \
  src/openssl/crypto/x509v3/v3_ocsp.c \
  src/openssl/crypto/x509v3/v3_pci.c \
  src/openssl/crypto/x509v3/v3_pcia.c \
  src/openssl/crypto/x509v3/v3_pcons.c \
  src/openssl/crypto/x509v3/v3_pku.c \
  src/openssl/crypto/x509v3/v3_pmaps.c \
  src/openssl/crypto/x509v3/v3_prn.c \
  src/openssl/crypto/x509v3/v3_purp.c \
  src/openssl/crypto/x509v3/v3_scts.c \
  src/openssl/crypto/x509v3/v3_skey.c \
  src/openssl/crypto/x509v3/v3_sxnet.c \
  src/openssl/crypto/x509v3/v3_utl.c
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := sqlite3
LOCAL_C_INCLUDES := app/src/ndn-cpp/contrib/sqlite3
LOCAL_SRC_FILES := src/ndn-cpp/contrib/sqlite3/sqlite3.c
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ndn-cpp
LOCAL_C_INCLUDES := \
  app/src/ndn-cpp/include app/src/openssl/include \
  app/src/ndn-cpp/contrib/sqlite3
LOCAL_SHARED_LIBRARIES := openssl sqlite3
LOCAL_SRC_FILES := \
  src/ndn-cpp/contrib/apache/apr_base64.c \
  src/ndn-cpp/src/c/control-parameters_c.c \
  src/ndn-cpp/src/c/errors.c \
  src/ndn-cpp/src/c/forwarding-flags.c \
  src/ndn-cpp/src/c/interest_c.c \
  src/ndn-cpp/src/c/name_c.c \
  src/ndn-cpp/src/c/network-nack_c.c \
  src/ndn-cpp/src/c/encoding/element-reader.c \
  src/ndn-cpp/src/c/encoding/tlv-0_2-wire-format_c.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-control-parameters.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-control-response.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-data.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-delegation-set.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-decoder.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-encoder.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-encrypted-content.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-interest.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-key-locator.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-lp-packet.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-name.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-signature-info.c \
  src/ndn-cpp/src/c/encoding/tlv/tlv-structure-decoder.c \
  src/ndn-cpp/src/c/encrypt/algo/aes-algorithm_c.c \
  src/ndn-cpp/src/c/lp/congestion-mark_c.c \
  src/ndn-cpp/src/c/lp/incoming-face-id_c.c \
  src/ndn-cpp/src/c/security/ec-private-key.c \
  src/ndn-cpp/src/c/security/ec-public-key.c \
  src/ndn-cpp/src/c/security/rsa-private-key.c \
  src/ndn-cpp/src/c/security/rsa-public-key.c \
  src/ndn-cpp/src/c/transport/socket-transport.c \
  src/ndn-cpp/src/c/transport/tcp-transport_c.c \
  src/ndn-cpp/src/c/util/blob_c.c \
  src/ndn-cpp/src/c/util/crypto.c \
  src/ndn-cpp/src/c/util/dynamic-uint8-array.c \
  src/ndn-cpp/src/c/util/ndn_memory.c \
  src/ndn-cpp/src/c/util/ndn_realloc.c \
  src/ndn-cpp/src/c/util/time.c \
  src/ndn-cpp/src/common.cpp \
  src/ndn-cpp/src/control-parameters.cpp \
  src/ndn-cpp/src/control-response.cpp \
  src/ndn-cpp/src/data.cpp \
  src/ndn-cpp/src/delegation-set.cpp \
  src/ndn-cpp/src/digest-sha256-signature.cpp \
  src/ndn-cpp/src/exclude.cpp \
  src/ndn-cpp/src/face.cpp \
  src/ndn-cpp/src/generic-signature.cpp \
  src/ndn-cpp/src/hmac-with-sha256-signature.cpp \
  src/ndn-cpp/src/interest-filter.cpp \
  src/ndn-cpp/src/interest.cpp \
  src/ndn-cpp/src/key-locator.cpp \
  src/ndn-cpp/src/link.cpp \
  src/ndn-cpp/src/meta-info.cpp \
  src/ndn-cpp/src/name.cpp \
  src/ndn-cpp/src/network-nack.cpp \
  src/ndn-cpp/src/node.cpp \
  src/ndn-cpp/src/signature.cpp \
  src/ndn-cpp/src/sha256-with-ecdsa-signature.cpp \
  src/ndn-cpp/src/sha256-with-rsa-signature.cpp \
  src/ndn-cpp/src/encoding/base64.cpp \
  src/ndn-cpp/src/encoding/element-listener.cpp \
  src/ndn-cpp/src/encoding/oid.cpp \
  src/ndn-cpp/src/encoding/protobuf-tlv.cpp \
  src/ndn-cpp/src/encoding/tlv-0_1-wire-format.cpp \
  src/ndn-cpp/src/encoding/tlv-0_1_1-wire-format.cpp \
  src/ndn-cpp/src/encoding/tlv-0_2-wire-format.cpp \
  src/ndn-cpp/src/encoding/tlv-wire-format.cpp \
  src/ndn-cpp/src/encoding/wire-format.cpp \
  src/ndn-cpp/src/encoding/der/der-exception.cpp \
  src/ndn-cpp/src/encoding/der/der-node.cpp \
  src/ndn-cpp/src/encrypt/consumer.cpp \
  src/ndn-cpp/src/encrypt/consumer-db.cpp \
  src/ndn-cpp/src/encrypt/encrypted-content.cpp \
  src/ndn-cpp/src/encrypt/group-manager.cpp \
  src/ndn-cpp/src/encrypt/group-manager-db.cpp \
  src/ndn-cpp/src/encrypt/interval.cpp \
  src/ndn-cpp/src/encrypt/producer.cpp \
  src/ndn-cpp/src/encrypt/producer-db.cpp \
  src/ndn-cpp/src/encrypt/repetitive-interval.cpp \
  src/ndn-cpp/src/encrypt/schedule.cpp \
  src/ndn-cpp/src/encrypt/sqlite3-consumer-db.cpp \
  src/ndn-cpp/src/encrypt/sqlite3-group-manager-db.cpp \
  src/ndn-cpp/src/encrypt/sqlite3-producer-db.cpp \
  src/ndn-cpp/src/encrypt/algo/aes-algorithm.cpp \
  src/ndn-cpp/src/encrypt/algo/encrypt-params.cpp \
  src/ndn-cpp/src/encrypt/algo/encryptor.cpp \
  src/ndn-cpp/src/encrypt/algo/rsa-algorithm.cpp \
  src/ndn-cpp/src/impl/delayed-call-table.cpp \
  src/ndn-cpp/src/impl/interest-filter-table.cpp \
  src/ndn-cpp/src/impl/pending-interest-table.cpp \
  src/ndn-cpp/src/impl/registered-prefix-table.cpp \
  src/ndn-cpp/src/lite/control-parameters-lite.cpp \
  src/ndn-cpp/src/lite/control-response-lite.cpp \
  src/ndn-cpp/src/lite/data-lite.cpp \
  src/ndn-cpp/src/lite/delegation-set-lite.cpp \
  src/ndn-cpp/src/lite/exclude-lite.cpp \
  src/ndn-cpp/src/lite/forwarding-flags-lite.cpp \
  src/ndn-cpp/src/lite/interest-lite.cpp \
  src/ndn-cpp/src/lite/key-locator-lite.cpp \
  src/ndn-cpp/src/lite/meta-info-lite.cpp \
  src/ndn-cpp/src/lite/name-lite.cpp \
  src/ndn-cpp/src/lite/network-nack-lite.cpp \
  src/ndn-cpp/src/lite/signature-lite.cpp \
  src/ndn-cpp/src/lite/encoding/element-listener-lite.cpp \
  src/ndn-cpp/src/lite/encoding/tlv-0_2-wire-format-lite.cpp \
  src/ndn-cpp/src/lite/encrypt/encrypted-content-lite.cpp \
  src/ndn-cpp/src/lite/encrypt/algo/aes-algorithm-lite.cpp \
  src/ndn-cpp/src/lite/encrypt/algo/encrypt-params-lite.cpp \
  src/ndn-cpp/src/lite/lp/congestion-mark-lite.cpp \
  src/ndn-cpp/src/lite/lp/incoming-face-id-lite.cpp \
  src/ndn-cpp/src/lite/lp/lp-packet-lite.cpp \
  src/ndn-cpp/src/lite/security/ec-private-key-lite.cpp \
  src/ndn-cpp/src/lite/security/ec-public-key-lite.cpp \
  src/ndn-cpp/src/lite/security/rsa-private-key-lite.cpp \
  src/ndn-cpp/src/lite/security/rsa-public-key-lite.cpp \
  src/ndn-cpp/src/lite/security/validity-period-lite.cpp \
  src/ndn-cpp/src/lite/transport/tcp-transport-lite.cpp \
  src/ndn-cpp/src/lite/transport/udp-transport-lite.cpp \
  src/ndn-cpp/src/lite/util/blob-lite.cpp \
  src/ndn-cpp/src/lite/util/crypto-lite.cpp \
  src/ndn-cpp/src/lite/util/dynamic-malloc-uint8-array-lite.cpp \
  src/ndn-cpp/src/lite/util/dynamic-uint8-array-lite.cpp \
  src/ndn-cpp/src/lp/congestion-mark.cpp \
  src/ndn-cpp/src/lp/incoming-face-id.cpp \
  src/ndn-cpp/src/lp/lp-packet.cpp \
  src/ndn-cpp/src/security/command-interest-signer.cpp \
  src/ndn-cpp/src/security/key-chain.cpp \
  src/ndn-cpp/src/security/key-params.cpp \
  src/ndn-cpp/src/security/safe-bag.cpp \
  src/ndn-cpp/src/security/security-exception.cpp \
  src/ndn-cpp/src/security/signing-info.cpp \
  src/ndn-cpp/src/security/validator-null.cpp \
  src/ndn-cpp/src/security/validity-period.cpp \
  src/ndn-cpp/src/security/verification-helpers.cpp \
  src/ndn-cpp/src/security/certificate/certificate-extension.cpp \
  src/ndn-cpp/src/security/certificate/certificate-subject-description.cpp \
  src/ndn-cpp/src/security/certificate/certificate.cpp \
  src/ndn-cpp/src/security/certificate/identity-certificate.cpp \
  src/ndn-cpp/src/security/certificate/public-key.cpp \
  src/ndn-cpp/src/security/identity/basic-identity-storage.cpp \
  src/ndn-cpp/src/security/identity/file-private-key-storage.cpp \
  src/ndn-cpp/src/security/identity/identity-manager.cpp \
  src/ndn-cpp/src/security/identity/identity-storage.cpp \
  src/ndn-cpp/src/security/identity/memory-identity-storage.cpp \
  src/ndn-cpp/src/security/identity/memory-private-key-storage.cpp \
  src/ndn-cpp/src/security/identity/private-key-storage.cpp \
  src/ndn-cpp/src/security/pib/pib-certificate-container.cpp \
  src/ndn-cpp/src/security/pib/pib-identity-container.cpp \
  src/ndn-cpp/src/security/pib/pib-identity.cpp \
  src/ndn-cpp/src/security/pib/pib-key-container.cpp \
  src/ndn-cpp/src/security/pib/pib-key.cpp \
  src/ndn-cpp/src/security/pib/pib-memory.cpp \
  src/ndn-cpp/src/security/pib/pib-sqlite3.cpp \
  src/ndn-cpp/src/security/pib/pib.cpp \
  src/ndn-cpp/src/security/pib/detail/pib-identity-impl.cpp \
  src/ndn-cpp/src/security/pib/detail/pib-key-impl.cpp \
  src/ndn-cpp/src/security/policy/config-policy-manager.cpp \
  src/ndn-cpp/src/security/policy/no-verify-policy-manager.cpp \
  src/ndn-cpp/src/security/policy/policy-manager.cpp \
  src/ndn-cpp/src/security/policy/self-verify-policy-manager.cpp \
  src/ndn-cpp/src/security/tpm/tpm-back-end-file.cpp \
  src/ndn-cpp/src/security/tpm/tpm-back-end-memory.cpp \
  src/ndn-cpp/src/security/tpm/tpm-back-end-osx.cpp \
  src/ndn-cpp/src/security/tpm/tpm-back-end.cpp \
  src/ndn-cpp/src/security/tpm/tpm-key-handle-memory.cpp \
  src/ndn-cpp/src/security/tpm/tpm-key-handle-osx.cpp \
  src/ndn-cpp/src/security/tpm/tpm-key-handle.cpp \
  src/ndn-cpp/src/security/tpm/tpm-private-key.cpp \
  src/ndn-cpp/src/security/tpm/tpm.cpp \
  src/ndn-cpp/src/security/v2/certificate-cache-v2.cpp \
  src/ndn-cpp/src/security/v2/certificate-fetcher-from-network.cpp \
  src/ndn-cpp/src/security/v2/certificate-fetcher-offline.cpp \
  src/ndn-cpp/src/security/v2/certificate-fetcher.cpp \
  src/ndn-cpp/src/security/v2/certificate-storage.cpp \
  src/ndn-cpp/src/security/v2/certificate-v2.cpp \
  src/ndn-cpp/src/security/v2/trust-anchor-container.cpp \
  src/ndn-cpp/src/security/v2/trust-anchor-group.cpp \
  src/ndn-cpp/src/security/v2/validation-error.cpp \
  src/ndn-cpp/src/security/v2/validation-policy-accept-all.cpp \
  src/ndn-cpp/src/security/v2/validation-policy-command-interest.cpp \
  src/ndn-cpp/src/security/v2/validation-policy-config.cpp \
  src/ndn-cpp/src/security/v2/validation-policy-from-pib.cpp \
  src/ndn-cpp/src/security/v2/validation-policy-simple-hierarchy.cpp \
  src/ndn-cpp/src/security/v2/validation-policy.cpp \
  src/ndn-cpp/src/security/v2/validation-state.cpp \
  src/ndn-cpp/src/security/v2/validator.cpp \
  src/ndn-cpp/src/security/v2/validator-config/config-checker.cpp \
  src/ndn-cpp/src/security/v2/validator-config/config-filter.cpp \
  src/ndn-cpp/src/security/v2/validator-config/config-name-relation.cpp \
  src/ndn-cpp/src/security/v2/validator-config/config-rule.cpp \
  src/ndn-cpp/src/transport/async-tcp-transport.cpp \
  src/ndn-cpp/src/transport/async-unix-transport.cpp \
  src/ndn-cpp/src/transport/tcp-transport.cpp \
  src/ndn-cpp/src/transport/transport.cpp \
  src/ndn-cpp/src/transport/udp-transport.cpp \
  src/ndn-cpp/src/transport/unix-transport.cpp \
  src/ndn-cpp/src/util/boost-info-parser.cpp \
  src/ndn-cpp/src/util/command-interest-generator.cpp \
  src/ndn-cpp/src/util/config-file.cpp \
  src/ndn-cpp/src/util/dynamic-uint8-vector.cpp \
  src/ndn-cpp/src/util/exponential-re-express.cpp \
  src/ndn-cpp/src/util/logging.cpp \
  src/ndn-cpp/src/util/memory-content-cache.cpp \
  src/ndn-cpp/src/util/segment-fetcher.cpp \
  src/ndn-cpp/src/util/sqlite3-statement.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-backref-manager.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-backref-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-component-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-component-set-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-matcher-base.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-pattern-list-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-pseudo-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-repeat-matcher.cpp \
  src/ndn-cpp/src/util/regex/ndn-regex-top-matcher.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ndn-example
LOCAL_LDLIBS := -llog -lm -latomic
LOCAL_SHARED_LIBRARIES := ndn-cpp
LOCAL_CFALGS := -O3 -UNDEBUG
LOCAL_C_INCLUDES := \
  $(LOCAL_PATH)/src/ndn-cpp/include
LOCAL_SRC_FILES := \
  src/ndn-cpp/examples/test-encode-decode-data.cpp
include $(BUILD_EXECUTABLE)

