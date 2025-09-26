





















from passlib.context import CryptContext
from passlib.apache import HtpasswdFile as _ApacheHtpasswdFile
from passlib.apache import htpasswd_context as _apache_htpasswd_ctx



_SHA512 = "ldap_salted_sha512"
_SHA256 = "ldap_salted_sha256"


def _make_kvmd_htpasswd_context() -> CryptContext:
    schemes = list(_apache_htpasswd_ctx.schemes())
    for alg in [_SHA256, _SHA512]:
        if alg in schemes:
            schemes.remove(alg)
        schemes.insert(0, alg)
    assert schemes[0] == _SHA512
    return CryptContext(
        schemes=schemes,
        default=_SHA512,
        bcrypt__ident="2y",
    )


_kvmd_htpasswd_ctx = _make_kvmd_htpasswd_context()



class KvmdHtpasswdFile(_ApacheHtpasswdFile):
    def __init__(self, path: str, new: bool=False) -> None:
        super().__init__(
            path=path,
            default_scheme=_SHA512,
            context=_kvmd_htpasswd_ctx,
            new=new,
        )
