import sys
import threading
import socket, time
import select
import signal
from ecdsa import SigningKey, VerifyingKey
import ecu_crypt


class ecu(object):
    # This keys is predifined keys
    generated_keys = {
    "1": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGPPAW9noa4kpGtr726a4eaw6DfZDApwWSKAKBggqhkjOPQMBAaE0AzIA\nBAjTbJ/6pKlIYcjgiQ5r+TtR3y/sPoKyZ9dWgY2mU52X61Sh75BOdocwx/lM7eoe\npA==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAECNNsn/qkqUhhyOCJDmv5O1HfL+w+\ngrJn11aBjaZTnZfrVKHvkE52hzDH+Uzt6h6k\n-----END PUBLIC KEY-----\n'
    },
    "2": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGKrmw5A/iFoysmkV+7UiEApBL8YQ1BgPFKAKBggqhkjOPQMBAaE0AzIA\nBBBkl3g06iaQQn1uMWTkt6NpmG2QoxA77dSnnabdvriwX0hrcS+TCiFjBL0U1w6v\nkw==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEEGSXeDTqJpBCfW4xZOS3o2mYbZCj\nEDvt1Kedpt2+uLBfSGtxL5MKIWMEvRTXDq+T\n-----END PUBLIC KEY-----\n'
    },
    "3": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGAEz0YPvpm6PPmcQq4ddfNUFe8vNmY4nzqAKBggqhkjOPQMBAaE0AzIA\nBEVvcECTJls/difo3Pl3sXFuEMvSNlf8z0c/MgiBZEJ5QixC8vIwFHp1Ba5WxdX5\ntA==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAERW9wQJMmWz92J+jc+XexcW4Qy9I2\nV/zPRz8yCIFkQnlCLELy8jAUenUFrlbF1fm0\n-----END PUBLIC KEY-----\n'
    },
    "4": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGOp34Wjeal46c+JzxNhpJfvcPM+X6hsJTaAKBggqhkjOPQMBAaE0AzIA\nBKcsHe7137ibXLBPD3QKQ5fXiudajkVX9xLNrOG6A3beJrtCmFi74d7wsHPxDyOx\nCg==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEpywd7vXfuJtcsE8PdApDl9eK51qO\nRVf3Es2s4boDdt4mu0KYWLvh3vCwc/EPI7EK\n-----END PUBLIC KEY-----\n'
    },
    "5": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGOcw5rXpHZOLATQ2SRBZiCdCR78CM+VxV6AKBggqhkjOPQMBAaE0AzIA\nBEaIFRWJxZuxoanLiS/JZQxkBOPlIl5iKXF7iY++DDHBJQ63WLv+aQgjJKThzMhd\nQg==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAERogVFYnFm7GhqcuJL8llDGQE4+Ui\nXmIpcXuJj74MMcElDrdYu/5pCCMkpOHMyF1C\n-----END PUBLIC KEY-----\n'
    },
    "6": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGPyRJDJGYbEfibZWE5kGkcapsdkdt4gyQ6AKBggqhkjOPQMBAaE0AzIA\nBOD37SRsy9dR8LyK8CBG2jaRbrMFpmcGZ3JjLcY/O1yaRgMVZCCnv/MOCkxFMhqx\nvw==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE4PftJGzL11HwvIrwIEbaNpFuswWm\nZwZncmMtxj87XJpGAxVkIKe/8w4KTEUyGrG/\n-----END PUBLIC KEY-----\n'
    },
    "7": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGAsL1r+Pk8gfirA2bfpT5S68NK4na0Ij66AKBggqhkjOPQMBAaE0AzIA\nBAyd2hbvhRXLZ/wkE2b/rsgBWyA5kA3lyuZ2xMm7HFEuWCm6HvNmzVzrXsaf0A7F\n7A==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEDJ3aFu+FFctn/CQTZv+uyAFbIDmQ\nDeXK5nbEybscUS5YKboe82bNXOtexp/QDsXs\n-----END PUBLIC KEY-----\n'
    },
    "8": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGC1gO/GKzXDnBB+kP//if95cigEith8OrqAKBggqhkjOPQMBAaE0AzIA\nBIrPF6u0aVsnJ+43mO5OIFP4krE7X7iAfALYXySgN7khXywf4KVoh2+eT6BD3mvm\n6A==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEis8Xq7RpWycn7jeY7k4gU/iSsTtf\nuIB8AthfJKA3uSFfLB/gpWiHb55PoEPea+bo\n-----END PUBLIC KEY-----\n'
    },
    "9": {
        "crypt_private":  b'-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANSUJHW+f7UWu9uZ\nOnkU3BngUsqlaoA2AbFeyPzQb5jVU9XF1frYXG4JS70T6RKquKvhkVMtcCWwR+P+\nGD83sdaXZJUHa0KbQUk/9uBYgzyxplK6mdpiJaIOvPZtKogE/gjzVL7INsH5/jSd\nZi8PrRUb00E8Zd9pIlI6iDkpTpZtAgMBAAECgYAzdrHk93t/YcOVBGGNkqk+cnpY\nqPdBltGOGT5bRjLeMzcal8yX7+1gjkuRuNJCPKZ8ph1Cn8t4tFaTMZ65H0ikE8/l\n5w6UfY7KGP8HMMYxRChLU5SjSbnSg0OXy0tWvY7s2R2o8OBeQIcX1tGrS9YmKIlA\nd/LtD7z672fY7sYNGQJBAPinMFhPC4hDUsIt6DfcAtDDNdlgCU86A1LId+lgeNz3\nI+z9H0qU4iDfSZwpz6UEOBoJz2p0bY8znj1P5aGzeEcCQQDa3BZAet8BpGsemhPZ\n1HflccF1zHiVPfhMhi1nwqszbHmQayVGTMqyV6zrEvfWSjb3JbBnr9rx4FT6sLif\nV0mrAkEA1cUuzA0Q9hIjGSvMhBGTHhVluz9UYZeXedk9NhepcRbL/RfUihMboXU1\n3JsZmF3bOY+LkZMNCdsvxLhmzDD2SwJBAK0QvMfgYdh6m/pm/KuUR/s4KTNtrSzX\nBDH/KIiUd60Cal65W5BryR2eFy8MoM7jgPOO6iAT/56lNo3GkTfvXmECQQCw2iTj\n5OhQDF7lqcfz/SzQTPknV/2PNn/JpPGTI3+CfpWtSAxIfF10D+iCU7Q4nzKiV78A\nc+DPBp8GfeuBrLGi\n-----END PRIVATE KEY-----\n' ,
        "crypt_public":  b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUlCR1vn+1FrvbmTp5FNwZ4FLK\npWqANgGxXsj80G+Y1VPVxdX62FxuCUu9E+kSqrir4ZFTLXAlsEfj/hg/N7HWl2SV\nB2tCm0FJP/bgWIM8saZSupnaYiWiDrz2bSqIBP4I81S+yDbB+f40nWYvD60VG9NB\nPGXfaSJSOog5KU6WbQIDAQAB\n-----END PUBLIC KEY-----\n' ,
        "signature_private":  b'-----BEGIN EC PRIVATE KEY-----\nMF8CAQEEGJL2RSN9G+897cyrSPJVfsK5pTKR3zsqBKAKBggqhkjOPQMBAaE0AzIA\nBJD8d+ZtPrqQ/lHfdNPbUWyK7qxnpeDWZK8XCQ7d/rgOhXeAjjy8zPUJBHSKoRGZ\nqw==\n-----END EC PRIVATE KEY-----\n' ,
        "signature_public":  b'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEkPx35m0+upD+Ud9009tRbIrurGel\n4NZkrxcJDt3+uA6Fd4COPLzM9QkEdIqhEZmr\n-----END PUBLIC KEY-----\n'
    },
    }

    def __init__(self, identifier, encrypt_message=True,  host='127.0.0.1', port=20202):
        # ASCON encryption parameters
        self.nonce = b'6jhuih4weh2uqw09'
        self.ad = b'CAN_FD'
        # self.session_key = open("session_key.txt",'rb').read()
        # ECU Identifier
        self.identifier = identifier
        # Create ECU socket to connect to bus
        self.socket_open = False
        self.ClientSocket = None
        self.host = host
        self.port = port
        self.sleep_in_select = 1
        self.max_total_size = 64
        self.signature_size = 48
        self.encrypt_message = encrypt_message      # when False do only signature to authenticate sender. if True also encrypt sent message with public key of the destination, but the message get bigger than 64 bytes
        self.max_payload_size = self.max_total_size - self.signature_size
        self.exit = False
        self.line_separator = f"\n----------  ECU {self.identifier}  --------------------------------------\n" \
                              "- Type message to send.\n"\
                              "- First char of the message is the address of destination\n" \
                              "- or type exit to finnish\n"
        # Cleanning up private keys
        for k, v in self.__class__.generated_keys.items():
            if k != self.identifier:
                v['private'] = None

    def embyulty_hex(self, msg):
        return ':'.join(map(hex, map(ord, msg)))

    def decrypt_and_show(self, Message_enc):
        # Start time
        start = time.time()
        sender = None
        signature = Message_enc[-self.signature_size:]
        all_message = Message_enc[:-self.signature_size]
        payload_enc = Message_enc[1:-self.signature_size]
        dest = Message_enc[0]
        # Trying to findout the sender
        for k, v in self.__class__.generated_keys.items():
            pem = VerifyingKey.from_pem(v['signature_public'].decode())
            try:
                if pem.verify(signature, all_message):
                    sender = k
                    break
            except Exception as e:
                pass
        # decript message
        if self.encrypt_message:
            payload_dec = ecu_crypt.my_decrypt(payload_enc, self.__class__.generated_keys[self.identifier]['crypt_private'])
        else:
            payload_dec = payload_enc
        print(f"ECU {self.identifier} received message from {sender}, destination {chr(dest)} \n"
              f"Complete message: {self.embyulty_hex(Message_enc.hex())} len;{len(Message_enc)}\n"
              f"Signature         {signature}\n"
              f"Payload encripted {payload_enc}\n"
              f"Payload decripted {payload_dec}")
        # Print execution time
        print(f"Execution time: {time.time() - start} milliseconds")
        print(self.line_separator)

    def encypt_and_send(self, destination, msg):
        # encript message here
        if self.encrypt_message:
            keypair = self.__class__.generated_keys.get(destination)
            if not keypair:
                print(f"The public key to destination {destination} not found")
                return
            enc_msg = ecu_crypt.my_encript(msg, keypair['crypt_public'])
        else:
            enc_msg = msg
        payload = destination.encode() + enc_msg
        # create signature using encripted msg
        pem = SigningKey.from_pem(self.__class__.generated_keys[self.identifier]['signature_private'].decode())
        signature = pem.sign_deterministic(payload)
        print(f"Sending message from {self.identifier} to {destination} \n"
              f"Plain msg: {msg} len{len(msg)}\n"
              f"Encrypted: {enc_msg} len{len(enc_msg)}\n"
              f"Signature {signature}, {len(signature)}")
        self.ClientSocket.send(payload + signature)
        print("Data has been sent!")

    def send_to_buss(self, msg):
        if not self.socket_open:
            print("Server is down")
            self.open_socket()
        else:
            dest = msg[0]
            msg = msg[1:]
            while msg:
                msg_slice = msg[:self.max_payload_size].encode()
                msg = msg[self.max_payload_size:]
                # Send message
                self.encypt_and_send(dest, msg_slice)

    def message_input(self):
        # Loop to way typing messages on keyboard and send to bus
        while True:
            print(self.line_separator)
            # Get input
            message = input("")
            if self.exit:
                break
            if message == 'exit':
                self.exit = True
                break
            if message:
                print("-----------------------------------------------")
                self.send_to_buss(message)

    # Receive function to receive messages from ECUs
    def receive_from_bus(self):
        # This is the thread processor
        while True:
            # Receive the encrypted message
            to_read = []
            if self.socket_open:
                to_read = [self.ClientSocket]
            readable, writable, exceptional = select.select(to_read, [], [], self.sleep_in_select)
            # print(f"{readable} {writable} {exceptional}")
            if not self.socket_open:
                self.open_socket()
                continue
            if self.exit:
                break
            if not readable:
                continue
            try:
                rcvdata = self.ClientSocket.recv(4096)
            except Exception as e:
                print("Probably server is down")
                self.open_socket()
                continue
            if not rcvdata:
                print("Probably server is down")
                self.open_socket()
                continue
            self.decrypt_and_show(rcvdata)

    def open_socket(self):
        if self.socket_open:
            self.ClientSocket.close()
            self.socket_open = False
        try:
            self.ClientSocket = socket.socket()
            self.ClientSocket.connect((self.host, self.port))
            self.socket_open = True
        except Exception as e:
            print(f"Error trying to connect to host {self.host}:{self.port} ")
            return False
        return True

    def proc(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        # Create a socket with bus
        if not self.open_socket():
            sys.exit(1)
        # create a thread to receive data in parallel with wayiting for user type message to send
        new_worker = threading.Thread(target=self.receive_from_bus)
        new_worker.start()
        self.message_input()
        new_worker.join()

    def signal_handler(self, sig, frame):
        print(self.line_separator)
        self.exit = True
        sys.exit(1)

