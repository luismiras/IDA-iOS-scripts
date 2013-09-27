"""
find_iOS_syscalls.py
luis@ringzero.net

This script looks for the syscall table. It finds the tables, renames
the handlers, and creates structures in the tables.

It is based on work from joker.c
    http://newosxbook.com/src.jl?tree=listings&file=8-joker.c

The sysent structure has changed between iOS 6.x and 7.x.

iOS 6.x

    00000000 sysent          struc ; (sizeof=0x18)
    00000000 sy_narg         DCW ?
    00000002 sy_resv         DCB ?
    00000003 sy_flags        DCB ?
    00000004 sy_call         DCD ?                   ; offset
    00000008 sy_arg_munge32  DCD ?
    0000000C sy_arg_munge64  DCD ?
    00000010 sy_return_type  DCD ?                   ; enum SY_RETURN_TYPE
    00000014 sy_arg_bytes    DCW ?
    00000016 padding         DCW ?
    00000018 sysent          ends

iOS 7.x

    00000000 sysent          struc ; (sizeof=0x14)
    00000000 sy_call         DCD ?                   ; offset
    00000004 sy_arg_munge32  DCD ?
    00000008 sy_arg_munge64  DCD ?
    0000000C sy_return_type  DCD ?                   ; enum SY_RETURN_TYPE
    00000010 sy_narg         DCW ?
    00000012 sy_arg_bytes    DCW ?
    00000014 sysent          ends

iOS 6.x has syscall names included in the kernel.
iOS 7.x removed the names from the kernel itself.
Xcode has the names in an include file (syscall.h), currently:
    /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/7.0 (11A465)/Symbols/usr/include/sys

from joker.c :
    * System call names auto-generated from iOS's <sys/syscall.h>
    * (/Developer/Platforms/iPhoneOS.platform/DeviceSupport/Latest/Symbols/usr/include/sys)
    *
    * can also be generated from OS X's <sys/syscall.h>, with minor tweaks (e.g. include
    *  ledger, pid_shutdown_sockets, etc..)
    *
    * Note, that just because a syscall is present, doesn't imply it's implemented -

NOTE: Be sure to change syscall_h_path to the include file.
"""

from idautils import XrefsTo,XrefTypeName
from idaapi import get_segm_by_name

################
# configuration
################
# path to syscall.h file from Xcode
syscall_h_path = None

# string naming convention in IDA Pro
string_prefix = "str"
#string_prefix = "a"

# pre/post naming conventions for syscalls
syscall_prefix = "SYS_"
syscall_postfix = ""

# standard segments
CSTRING_SEGNAME = "__TEXT:__cstring"
TEXT_SEGNAME =    "__TEXT:__text"
DATA_SEGNAME =    "__DATA:__const"


####################
# utility functions
####################
def make_name(name, addr):
    """

    """
    if MakeNameEx(addr, name, SN_PUBLIC | SN_NOWARN) != 1:
        return False
    return True


##########
# Classes
##########
class KernelInfo(object):
    """
    The KernelInfo class can rename iOS 6.x and 7.x syscalls
    """
    def __init__(self):
        """

        """
        self.cstring_seg = None
        self.text_seg = None
        self.data_seg = None
        self.iOSversion = None
        self.syscall_names = []
        self.syscall_addrs = []
        self.maxsyscall = None
        self.sysent = None
        return


    def parse(self):
        """
        parse() does the main processing
        returns True  on success
                False on any errors
        """
        if self._get_kernel_version() == False:
            return False

        if self._lookup_segments() == False:
            return False

        if self._get_syscall_names() == False:
            return False

        if self._get_syscall_addresses() == False:
            return False

        if self._create_enum_and_sysent() == False:
            return False

        if self._name_syscalls() == False:
            return False
            
        if self._create_syscall_structures() == False:
            return False

        return True


    #################
    # helper methods 
    #################
    def _get_kernel_version(self):
        """
        Determines kernel version based on exported '_version'
        """

        print "[+] kernel version:"
        kernel_string = GetString(LocByName("_version"))
        print "    %s" % kernel_string
        # Darwin Kernel Version 13.0.0: Sun Dec 16 19:58:12 PST 2012; root:xnu-2107.7.55~11/RELEASE_ARM_S5L8930X
        kversion = kernel_string.split(":")[0].split()[3]

        if kversion == "13.0.0":
            self.iOSversion = 6
        elif kversion == "14.0.0":
            self.iOSversion = 7
        else:
            print "[!] Unknown kernel version!"
            return False

        print "[+] Detected %d.x kernel" % self.iOSversion
        return True


    def _lookup_segments(self):
        """
        Looks up __TEXT:__cstring, __TEXT:__text, __DATA:__const
        """

        self.cstring_seg = get_segm_by_name(CSTRING_SEGNAME)
        if type(self.cstring_seg) == type(None):
            print "[!] Error looking up %s" % CSTRING_SEGNAME
            return False

        self.text_seg = get_segm_by_name(TEXT_SEGNAME)
        if type(self.text_seg) == type(None):
            print "[!] Error looking up %s" % TEXT_SEGNAME
            return False

        self.data_seg = get_segm_by_name(DATA_SEGNAME)
        if type(self.data_seg) == type(None):
            print "[!] Error looking up %s" % DATA_SEGNAME
            return False

        return True


    #############################
    # enum and structure methods
    #############################
    def _add_SY_RETURN_TYPE_enum(self):
        """
        Adds SY_RETURN_TYPE to IDA enums
        """
        # check if enum already exists
        if GetEnum("SY_RETURN_TYPE") != BADADDR:
            print "[+] Enum \"SY_RETURN_TYPE\" already exists"
            return True

        i = AddEnum(-1,"SY_RETURN_TYPE",0x1100000)
        if AddConstEx(i,"_SYSCALL_RET_NONE", 0, -1) or AddConstEx(i,"_SYSCALL_RET_INT_T", 0X1, -1) or\
           AddConstEx(i,"_SYSCALL_RET_UINT_T", 0X2, -1) or AddConstEx(i,"_SYSCALL_RET_OFF_T", 0X3, -1) or\
           AddConstEx(i,"_SYSCALL_RET_ADDR_T", 0X4, -1) or AddConstEx(i,"_SYSCALL_RET_SIZE_T", 0X5, -1) or\
           AddConstEx(i,"_SYSCALL_RET_SSIZE_T", 0X6, -1) or AddConstEx(i,"_SYSCALL_RET_UINT64_T", 0X7, -1):
            print "[!] Error creating SY_RETURN_TYPE"
            return False

        print "[+] Enum \"SY_RETURN_TYPE\" created"
        return True


    def _add_sysent_structure(self):
        """
        Adds 'sysent' structure for iOS6/7 to IDA
        """
        if GetStrucIdByName("sysent") != BADADDR:
            print "[+] Structure \"sysent\" already exists"
            return True

        i = AddStrucEx(-1,"sysent",0)

        if self.iOSversion == 6:
            if AddStrucMember(i,"sy_narg", 0, 0x10000400, -1, 2) or\
               AddStrucMember(i,"sy_resv", 0X2, 0x000400, -1, 1) or\
               AddStrucMember(i,"sy_flags", 0X3, 0x000400, -1, 1) or\
               AddStrucMember(i,"sy_call", 0X4, 0x20500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002) or\
               AddStrucMember(i,"sy_arg_munge32", 0X8, 0x20000400, -1, 4) or\
               AddStrucMember(i,"sy_arg_munge64", 0XC, 0x20000400, -1, 4) or\
               AddStrucMember(i,"sy_return_type", 0X10, 0x20800400, GetEnum("SY_RETURN_TYPE"), 4) or\
               AddStrucMember(i,"sy_arg_bytes", 0X14, 0x10000400, -1, 2) or\
               AddStrucMember(i,"padding", 0X16, 0x10000400, -1, 2):
                print"[!] Error creating sysent structure"
                return False

        elif self.iOSversion == 7:
            if AddStrucMember(i,"sy_call", 0, 0x20500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002) or\
               AddStrucMember(i,"sy_arg_munge32", 0X4, 0x20000400, -1, 4) or\
               AddStrucMember(i,"sy_arg_munge64", 0X8, 0x20000400, -1, 4) or\
               AddStrucMember(i,"sy_return_type", 0XC, 0x20800400, GetEnum("SY_RETURN_TYPE"), 4) or\
               AddStrucMember(i,"sy_narg", 0X10, 0x10000400, -1, 2) or\
               AddStrucMember(i,"sy_arg_bytes", 0X12, 0x10000400, -1, 2):
                print"[!] Error creating sysent structure"
                return False

        else:
            print "[!] _add_sysent_structure(), unsupported iOS version: %d" % version
            return False

        print "[+] Structure \"sysent\" created"
        return True


    ##################
    # syscall methods
    ##################
    def _create_syscall_structures(self):
        """

        """
        sid = GetStrucIdByName('sysent')
        if sid == BADADDR:
            print "[!] Error: GetStrucIdByName failed"
            return False

        sysent_size = GetStrucSize(sid)
        if sysent_size == BADADDR:
            print "[!] Error: GetStrucSize failed"
            return False

        for i in range(len(self.syscall_addrs)):
            addr = self.sysent + (i*sysent_size)
            MakeUnknown(addr, sysent_size, DOUNK_SIMPLE)
            if MakeStructEx(addr, sysent_size, "sysent") == 0:
                print "[!] Error: MakeStructEx failed %x" % addr
                return False

            # comment with either syscall name or #xxx 
            name = self.syscall_names[i]
            if i == 0: # first syscall is enosys
                name = "#0"
            if name[0] != "#":
                name = syscall_prefix+name+syscall_postfix
            MakeComm(addr, name)

        # rename sysent base
        if make_name("syscall_table", self.sysent) == False:
            print "[!] make_name(\"syscall_table\", %x) Failed" % self.sysent
            return False
        print "[+] Created %d sysent structures" % len(self.syscall_addrs)
        return True


    def _name_syscalls(self):
        """

        """
        for i in range(len(self.syscall_names)):
            name = self.syscall_names[i]
            if i == 0: # first syscall is enosys
                name = "enosys"

            if name[0] == "#":
                continue

            full_name = syscall_prefix+name+syscall_postfix
            addr = self.syscall_addrs[i]
            if addr % 4 > 0:
                addr -= 1

            # need to check if already named
            if Name(addr).find(syscall_prefix) != -1:
                print "[!] %s already named %s" % (full_name, Name(addr))
                continue

            if make_name(full_name, addr) == False:
                print "[!] make_name(\"%s\", %x) Failed" % (full_name, addr)

        print "[+] Named %d syscalls" % len(self.syscall_names)
        return True


    def _create_enum_and_sysent(self):
        """

        """
        if self._add_SY_RETURN_TYPE_enum() == False:
            return False
        if self._add_sysent_structure() == False:
            return False
        return True


    def _get_syscall_addresses(self):
        """

        """
        if self.iOSversion == 6:
            if self._find_iOS6_syscall_table() == False:
                print "[!] Error: Syscall table not found"
                return False
            print "[+] Syscall table, sysent: %x" % self.sysent

            if self._get_iOS6_syscall_addrs() == False:
                return False

        elif self.iOSversion == 7:
            if self._find_iOS7_syscall_table() == False:
                print "[!] Error: Syscall table not found"
                return False
            print "[+] Syscall table, sysent: %x" % self.sysent
            if self._get_iOS7_syscall_addrs() == False:
                return False

        else:
            return False

        if len(self.syscall_names) != len(self.syscall_addrs):
            print "[!] Error: syscall_names: %d != syscall_addrs: %d" % (len(self.syscall_names), len(self.syscall_addrs))
            return False

        print "[+] Found %d syscall structures" % len(self.syscall_addrs)
        return True


    def _get_syscall_names(self):
        """

        """
        print "[+] ---- syscall lookup -----"
        if self.iOSversion == 7 and syscall_h_path == None:
            print "[!] iOS7.x requires syscall.h path, set syscall_h_path to retrieve syscall names."
            return False


        if self.iOSversion == 6:
            if self._lookup_syscall_names_from_kernel() == False:
                print "[!] Error: _lookup_syscall_names_from_kernel()"
                return False
            print "[+] Found %d syscall names" % len(self.syscall_names)
        elif self.iOSversion == 7:
            print "[+] Attempting syscall.h name lookup, using path:"
            print "    %s" % syscall_h_path
            if self._lookup_syscall_names_from_syscall_h() == False:
                print "[!] Error: _get_syscall_names()"
                return False
            print "[+] Found %d syscall names, syscall.h MAXSYSCALL: %d" % (len(self.syscall_names), self.maxsyscall)
        else:
            return False

        return True


    ###########################
    # iOS 6.x specific methods
    ###########################
    def _lookup_syscall_names_from_kernel(self):
        """
        returns syscall list
        6.1.2 kernel has syscall names as strings in __TEXT:__cstring segment
        """
        syscall_ea = LocByName(string_prefix+"Syscall")

        if syscall_ea < self.cstring_seg.startEA or syscall_ea > self.cstring_seg.endEA:
            return False

        seg_start_ea = self.cstring_seg.startEA
        seg_end_ea = self.cstring_seg.endEA

        xrefs = list(XrefsTo(syscall_ea, 0))
        if len(xrefs) != 1:
            return False

        xref = xrefs[0]
        addr = xref.frm 

        while addr != BADADDR:
            t = Dword(addr)

            # test if in __TEXT:__cstring segment
            if t < seg_start_ea or t > seg_end_ea:
                break
            
            # get Name, check for str
            tname = Name(t)
            if tname.find(string_prefix) == 0:
                str_content = GetString(t)
                self.syscall_names.append(str_content)

            addr += 4

        return True


    def _find_iOS6_syscall_table(self):
        """

        """
        curr_addr = self.data_seg.startEA
        while curr_addr < self.data_seg.endEA:
            if Dword(curr_addr) == 0    and Dword(curr_addr+4)  == 0 and Dword(curr_addr+8)  == 1 and\
               Dword(curr_addr+12) == 0 and Dword(curr_addr+16) == 1 and Dword(curr_addr+24) == 0 and\
               Dword(curr_addr+28) == 0 and Dword(curr_addr+32) == 0 and Dword(curr_addr+36) == 4:
                self.sysent = curr_addr - 8
                break
            curr_addr += 4

        if self.sysent == None:
            return False

        return True


    def _get_iOS6_syscall_addrs(self):
        """
        currently always returns True

        bottom of syscall table

        __DATA:__const:802F2A28                 sysent <2, 0, 0, 0x801CED69, 0, 0, _SYSCALL_RET_INT_T, 8, 0>
        __DATA:__const:802F2A40 unk_802F2A40    DCB    5                ; DATA XREF: sub_801CF720+40o
        __DATA:__const:802F2A40                                         ; sub_801CF720+48o
        __DATA:__const:802F2A41                 DCB    0
        __DATA:__const:802F2A42                 DCB    0
        __DATA:__const:802F2A43                 DCB    0
        __DATA:__const:802F2A44                 DCD sub_801D0FC0+1
        __DATA:__const:802F2A48                 DCD sub_801D0FC4+1
        __DATA:__const:802F2A4C                 DCD sub_801D0FC8+1
        __DATA:__const:802F2A50                 DCD sub_801D0FCC+1
        __DATA:__const:802F2A54                 DCD sub_801D1188+1
        __DATA:__const:802F2A58                 DCD sub_801D119C+1
        __DATA:__const:802F2A5C                 DCD sub_801D1230+1
        """
        curr_addr = self.sysent

        while curr_addr < self.data_seg.endEA:
            if len(list(XrefsTo(curr_addr,0))) > 0 and curr_addr != self.sysent:
                break

            if Dword(curr_addr+0x10) > 10: # curr max return type is 7
                break

            addr = Dword(curr_addr+4)

            # should add check verify target in text segment
            self.syscall_addrs.append(addr)
            curr_addr += 0x18

        return True



    ###########################
    # iOS 7.x specific methods
    ###########################
    def _lookup_syscall_names_from_syscall_h(self):
        """

        """
        if syscall_h_path == None:
            return False

        try:
            fd = open(syscall_h_path, "r")
            lines = fd.readlines()
            fd.close()
        except:
            print "[!] syscall.h: Failure opening: %s" % syscall_h_path
            return False

        # skip to first syscall
        i = 0
        while lines[i].find("SYS_syscall") < 0:
            i += 1

        # SYS_MAXSYSCALL is the first line after last syscall
        while lines[i].find("SYS_MAXSYSCALL") < 0:
            line = lines[i].strip()

            if line[0] == '#':
                SYS_name = (line.split()[1])
                if SYS_name.find("SYS_") != 0:
                    print "[!] syscall.h: parse error %s:%d  %s" % (syscall_h_path, i, lines[i])
                    return False
                self.syscall_names.append(SYS_name[4:])
            elif line[0] == '/':
                # /* 8  old creat */
                syscall_num = line.split()[1]
                # unassigned syscalls will be listed as #xxx, 
                # same format as the internal iOS 6.x list
                self.syscall_names.append("#%s" % syscall_num)
            else:
                print "[!] syscall.h: parse error %s:%d  %s" % (syscall_h_path, i, lines[i])
                return False
            i += 1

        self.maxsyscall = int(lines[i].split()[2])
        return True


    def _find_iOS7_syscall_table(self):
        """
        array of syscalls until sy_call is null
        """
        curr_addr = self.data_seg.startEA
        while curr_addr < self.data_seg.endEA:
            if Dword(curr_addr) == 0    and Dword(curr_addr+4)  == 0 and Dword(curr_addr+8)  == 1 and\
               Dword(curr_addr+12) == 0 and Dword(curr_addr+20) == 0 and Dword(curr_addr+24) == 0 and\
               Dword(curr_addr+28) == 0 and Dword(curr_addr+32) == 0x40001:
                self.sysent = curr_addr - 4
                break

            curr_addr += 4

        if self.sysent == None:
            return False
        return True


    def _get_iOS7_syscall_addrs(self):
        """
        currently always returns True
        """
        curr_addr = self.sysent

        while curr_addr < self.data_seg.endEA:
            addr = Dword(curr_addr)
            if addr == 0: # end of list
                break

            # should add check verify target in text segment
            self.syscall_addrs.append(addr)
            curr_addr += 0x14

        return True

###########
def main():
    print "-----------------------"
    print "Find iOS syscalls v0.01"
    print "luis@ringzero.net\n"

    kinfo = KernelInfo()

    if kinfo.parse() == False:
        print "[!] exiting"
        return
    
    print "[+] done!"        

main()
