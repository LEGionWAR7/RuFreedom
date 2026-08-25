# -*- mode: python ; coding: utf-8 -*-
import io as _io
import re as _re

from PyInstaller.utils.hooks import collect_all

# --- версия: один источник на всё -----------------------------------------
# Номер лежит в dpi/update.py и оттуда же попадает в паспорт exe. Раньше он
# был прописан в двух местах и рано или поздно разъехался бы: программа
# сообщала бы одну версию, свойства файла -- другую.
import os as _os
_root = globals().get('SPECPATH') or _os.getcwd()
_src = _io.open(_os.path.join(_root, 'dpi', 'update.py'), encoding='utf-8').read()
VERSION = _re.search(r'^VERSION\s*=\s*"([^"]+)"', _src, _re.M).group(1)
_parts = tuple(int(x) for x in VERSION.split('.')) + (0, 0, 0, 0)
_v4 = _parts[:4]

_io.open(_os.path.join(_root, 'version_info.txt'), 'w', encoding='utf-8').write(f"""# -*- coding: utf-8 -*-
# СОБИРАЕТСЯ АВТОМАТИЧЕСКИ из VERSION в dpi/update.py. Не править руками.
# Без этого ресурса exe безымянный, и эвристика антивирусов считает это
# признаком зловреда.
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={_v4}, prodvers={_v4},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'RuFreedom'),
         StringStruct('FileDescription', 'RuFreedom - obhod blokirovok (DPI bypass)'),
         StringStruct('FileVersion', '{VERSION}'),
         StringStruct('InternalName', 'RuFreedom'),
         StringStruct('LegalCopyright', 'Free software, MIT-style. WinDivert (LGPL) included.'),
         StringStruct('OriginalFilename', 'RuFreedom.exe'),
         StringStruct('ProductName', 'RuFreedom'),
         StringStruct('ProductVersion', '{VERSION}'),
         StringStruct('Comments', 'Local DPI bypass utility. Does not collect or send user data.')]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""")
print('[spec] версия', VERSION)

# В сборку кладём образцы настроек, но НЕ личные файлы: settings.json --
# это состояние конкретного компьютера (какие сервисы у человека закрыты,
# что подобралось), и раздавать его вместе с программой незачем.
datas = [('assets', 'assets'), ('web', 'web')]
for _name in ('rufreedom.ini', 'hostlist.txt'):
    _p = _os.path.join(_root, 'config', _name)
    if _os.path.isfile(_p):
        datas.append((_p, 'config'))
binaries = []
hiddenimports = ['clr']
for _pkg in ('webview', 'pydivert', 'pystray'):
    _d, _b, _h = collect_all(_pkg)
    datas += _d; binaries += _b; hiddenimports += _h


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # cryptography стоит в системе ради tg-ws-proxy, но нам не нужен —
    # иначе он добавляет к сборке лишние 4 МБ
    excludes=['customtkinter', 'tkinter', 'cryptography', 'pyperclip'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RuFreedom',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX выключен намеренно: упакованный exe -- главный триггер
    # эвристики антивирусов (Program:Win32/*!ml).
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['assets\\icon.ico'],
    version='version_info.txt',
)
