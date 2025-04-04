#pragma once

enum tc_act {
    TC_ACT_UNSPEC = -1,
    TC_ACT_OK = 0,
    TC_ACT_RECLASSIFY = 1,
    TC_ACT_SHOT = 2,
    TC_ACT_PIPE = 3,
    TC_ACT_STOLEN = 4,
    TC_ACT_QUEUED = 5,
    TC_ACT_REPEAT = 6,
    TC_ACT_REDIRECT = 7,
    TC_ACT_JUMP = 0x10000000
};
