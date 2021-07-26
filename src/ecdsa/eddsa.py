"""Implementation of Edwards Digital Signature Algorithm."""

from . import ellipticcurve
from ._compat import remove_whitespace

# edwards25519, defined in RFC7748
_p = 2 ** 255 - 19
_a = -1
_d = int(
    remove_whitespace(
        "370957059346694393431380835087545651895421138798432190163887855330"
        "85940283555"
    )
)
_h = 8

_Gx = int(
    remove_whitespace(
        "151122213495354007725011514095885315114540126930418572060461132"
        "83949847762202"
    )
)
_Gy = int(
    remove_whitespace(
        "463168356949264781694283940034751631413079938662562256157830336"
        "03165251855960"
    )
)
_r = 2 ** 252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED

curve_ed25519 = ellipticcurve.CurveEdTw(_p, _a, _d, _h)
generator_ed25519 = ellipticcurve.PointEdwards(
    curve_ed25519, _Gx, _Gy, 1, _Gx * _Gy % _p, _r
)


# edwards448, defined in RFC7748
_p = 2 ** 448 - 2 ** 224 - 1
_a = 1
_d = -39081 % _p
_h = 4

_Gx = int(
    remove_whitespace(
        "224580040295924300187604334099896036246789641632564134246125461"
        "686950415467406032909029192869357953282578032075146446173674602635"
        "247710"
    )
)
_Gy = int(
    remove_whitespace(
        "298819210078481492676017930443930673437544040154080242095928241"
        "372331506189835876003536878655418784733982303233503462500531545062"
        "832660"
    )
)
_r = 2 ** 446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D

curve_ed448 = ellipticcurve.CurveEdTw(_p, _a, _d, _h)
generator_ed448 = ellipticcurve.PointEdwards(
    curve_ed448, _Gx, _Gy, 1, _Gx * _Gy % _p, _r
)
