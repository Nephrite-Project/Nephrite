#ifndef VSS_HANDLES_H
#define VSS_HANDLES_H

/* Constants for QGA VSS Provider */

#define QGA_PROVIDER_NAME "Nephrite Guest Agent VSS Provider"
#define QGA_PROVIDER_LNAME L(QGA_PROVIDER_NAME)
#define QGA_PROVIDER_VERSION L(NEPHRITE_VERSION)
#define QGA_PROVIDER_REGISTRY_ADDRESS "SYSTEM\\CurrentControlSet"\
                                      "\\Services"\
                                      "\\" QGA_PROVIDER_NAME

#define EVENT_NAME_FROZEN  "Global\\NephriteGAVSSEvent-frozen"
#define EVENT_NAME_THAW    "Global\\NephriteGAVSSEvent-thaw"
#define EVENT_NAME_TIMEOUT "Global\\NephriteGAVSSEvent-timeout"

#endif
