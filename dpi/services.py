"""
Каталог сервисов, разбитый на группы.

Каждая группа — это отдельная карточка в интерфейсе и, что важнее, отдельный
профиль обхода: Epic, Discord и YouTube режут по-разному, и то, что пробивает
один сервис, не пробивает другой. Раньше стратегия была одна на всех, и
приходилось выбирать, кем пожертвовать.

Поля группы:
  title   — название для интерфейса;
  icon    — id значка в SVG-спрайте (web/index.html);
  accent  — цвет карточки;
  probe   — хосты, на которых автоподбор проверяет, пробило или нет;
  domains — корневые домены (поддомены движок подхватывает сам);
  udp     — диапазон UDP-портов, если у сервиса есть свой не-QUIC трафик
            (голос Discord живёт на 50000-65535).
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List, Optional

GROUPS: "OrderedDict[str, dict]" = OrderedDict()

GROUPS["epic"] = {
    "title": "Epic Games",
    "icon": "i-svc-epic",
    "accent": "#e6e8ec",
    "probe": ["www.epicgames.com", "store.epicgames.com"],
    "domains": [
        "epicgames.com", "fortnite.com", "unrealengine.com", "epicgames.dev",
        "fallguys.com", "rocketleague.com", "easyanticheat.com",
        "easyanticheat.net", "epicgames-download1.akamaized.net",
    ],
}

GROUPS["steam"] = {
    "title": "Steam",
    "icon": "i-svc-steam",
    "accent": "#66c0f4",
    "probe": ["steamcommunity.com", "store.steampowered.com"],
    "domains": [
        "steampowered.com", "steamcommunity.com", "steamstatic.com",
        "steamserver.net", "steamgames.com", "steamusercontent.com",
        "steamcontent.com", "valvesoftware.com", "dota2.com",
        "counter-strike.net",
    ],
}

GROUPS["riot"] = {
    "title": "Riot Games",
    "icon": "i-svc-riot",
    "accent": "#ff4655",
    "probe": ["www.riotgames.com"],
    "domains": [
        "riotgames.com", "leagueoflegends.com", "riotcdn.net", "valorant.com",
        "rgpub.io",
    ],
}

GROUPS["blizzard"] = {
    "title": "Blizzard",
    "icon": "i-svc-blizzard",
    "accent": "#00aeff",
    "probe": ["eu.battle.net"],
    "domains": [
        "battle.net", "blizzard.com", "playoverwatch.com", "worldofwarcraft.com",
        "blizzardgames.cn", "battlenet.com.cn",
    ],
}

GROUPS["games"] = {
    "title": "Другие игры",
    "icon": "i-svc-games",
    "accent": "#a78bfa",
    "probe": ["www.ea.com", "www.rockstargames.com"],
    "domains": [
        "ea.com", "easports.com", "origin.com", "respawn.com", "playapex.com",
        "pubg.com", "pubgmobile.com", "krafton.com",
        "rockstargames.com", "rockstargames.net", "take2games.com",
        "ubisoft.com", "ubi.com", "ubisoftconnect.com", "rainbow6.com",
        "gog.com", "playstation.com", "playstation.net",
        "xbox.com", "xboxlive.com", "xboxservices.com",
        "nintendo.com", "nintendo.net",
        "roblox.com", "rbxcdn.com", "minecraft.net", "mojang.com",
        "callofduty.com", "activision.com",
        "hoyoverse.com", "mihoyo.com", "yuanshen.com",
        "square-enix.com", "finalfantasyxiv.com", "bungie.net",
        "pathofexile.com", "warframe.com", "guildwars2.com", "arena.net",
        "eveonline.com", "robertsspaceindustries.com", "albiononline.com",
        "deadbydaylight.com", "innersloth.com", "wargaming.net",
        "itch.io", "humblebundle.com", "battleye.com", "faceit.com",
        "esea.net", "playfab.com", "teamspeak.com",
    ],
}

GROUPS["cdn"] = {
    "title": "Сети доставки",
    "icon": "i-svc-cdn",
    "accent": "#5eead4",
    "probe": ["www.fastly.com", "www.akamai.com"],
    "domains": [
        "akamaized.net", "akamai.net", "akamaihd.net", "fastly.net",
        "cloudfront.net", "llnwd.net", "edgecast.com", "cdn77.org",
        "gcore.com", "gcdn.co",
    ],
}

GROUPS["discord"] = {
    "title": "Discord",
    "icon": "i-svc-discord",
    "accent": "#5865f2",
    "probe": ["discord.com", "gateway.discord.gg"],
    "domains": [
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
        "discord.media", "discord.gift", "dis.gd", "discordcdn.com",
    ],
    # Голосовые каналы ходят обычным UDP (не QUIC). Диапазоны узкие и взяты
    # по факту: 50000-50100 у старых голосовых серверов, 19294-19344 у новых.
    # Широкий 50000-65535 задевал бы игровой трафик без всякой нужды.
    "udp": [(19294, 19344), (50000, 50100)],
}

GROUPS["telegram"] = {
    # Карточки у Telegram нет: обход DPI ему не помогает (закрыт по IP), и
    # галочка «включить обход» только вводила бы в заблуждение. Ему отведена
    # отдельная вкладка со встроенным мостом.
    "card": False,
    "title": "Telegram",
    "icon": "i-svc-telegram",
    "accent": "#2aabee",
    "probe": ["telegram.org", "t.me"],
    "domains": [
        "telegram.org", "telegram.me", "t.me", "telegra.ph",
        "telesco.pe", "cdn-telegram.org", "comments.app", "tdesktop.com",
    ],
}

GROUPS["youtube"] = {
    "title": "YouTube",
    "icon": "i-svc-youtube",
    "accent": "#ff2d46",
    # Проверяем не главную страницу, а API: именно через него грузятся Shorts
    # и рекомендации, и режут чаще всего его, а не youtube.com.
    "probe": ["youtubei.googleapis.com", "www.youtube.com"],
    "domains": [
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
        "ggpht.com", "youtube-nocookie.com", "youtubekids.com",
        # API и внутренние имена — без них Shorts и лента остаются пустыми
        "youtubei.googleapis.com", "youtube.googleapis.com",
        "youtubeembeddedplayer.googleapis.com", "jnn-pa.googleapis.com",
        "yt3.googleusercontent.com",
        "youtube-ui.l.google.com", "wide-youtube.l.google.com",
        "yt-video-upload.l.google.com", "ytimg.l.google.com",
    ],
}

GROUPS["twitch"] = {
    "title": "Twitch",
    "icon": "i-svc-twitch",
    "accent": "#9146ff",
    "probe": ["www.twitch.tv", "gql.twitch.tv"],
    "domains": [
        "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net",
    ],
}

GROUPS["ai"] = {
    "title": "Нейросети",
    "icon": "i-svc-ai",
    "accent": "#f59e0b",
    "probe": ["chatgpt.com", "claude.ai"],
    "domains": [
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
        "sora.com", "anthropic.com", "claude.ai",
        "gemini.google.com", "aistudio.google.com",
        "generativelanguage.googleapis.com", "copilot.microsoft.com",
        "perplexity.ai", "mistral.ai", "character.ai", "x.ai", "grok.com",
        "huggingface.co", "midjourney.com", "suno.com",
    ],
}

GROUP_IDS: List[str] = list(GROUPS.keys())

# Группы, которые показываются карточками и участвуют в обходе DPI.
CARD_IDS: List[str] = [g for g, m in GROUPS.items() if m.get("card", True)]


def has_card(gid: str) -> bool:
    g = GROUPS.get(gid)
    return bool(g and g.get("card", True))

# Домены античитов и игровой авторизации. Их обход не трогает НИКОГДА.
#
# Причина простая и проверяемая: они не заблокированы (проверено — все
# отвечают напрямую), а десинхронизация ломает им рукопожатие. Игра при этом
# не проходит проверку и не пускает внутрь — со стороны это выглядит как
# «античит блокирует обход», хотя на деле обход ломает античит.
#
# Обход при этом продолжает работать для Discord и всего остального: выключать
# его целиком на время игры не нужно, достаточно обойти эти домены стороной.
ANTICHEAT_DOMAINS: List[str] = [
    "easyanticheat.net", "easyanticheat.com", "eac-cdn.epicgames.com",
    "battleye.com", "battleye.net",
    "riotgames.com", "riotcdn.net", "playvalorant.com", "leagueoflegends.com",
    "faceit.com", "faceit-cdn.net", "esea.net",
    "playfab.com", "playfabapi.com",          # матчмейкинг и профили игроков
    "epicgames.dev", "unrealengine.com",       # EOS: вход и сессии
    "gameguard.co.kr", "nprotect.com",
]

# Домены, которые обход не трогает НИКОГДА, даже в режиме «весь трафик».
# Их никто не блокирует, а десинхронизация им только вредит: банковские и
# государственные сервисы особенно чувствительны к нестандартным TCP-потокам,
# и сломать вход в банк ради обхода, который там не нужен, — плохая сделка.
NEVER_TOUCH: List[str] = [
    # государственные и платёжные
    "gosuslugi.ru", "gov.ru", "nalog.ru", "mos.ru", "spb.ru",
    "sber.ru", "sberbank.ru", "sberbank.com", "vtb.ru", "tbank.ru",
    "tinkoff.ru", "cdn-tinkoff.ru", "alfabank.ru", "gazprombank.ru", "gpb.ru",
    "psbank.ru", "rosbank.ru", "rshb.ru", "abr.ru", "bankline.ru",
    "mtsdengi.ru", "tochka.com", "tochka-tech.com",
    # крупные российские сервисы
    "yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net",
    "yandexcloud.net", "mail.ru", "vk.com", "vk.ru", "vk.me", "vkvideo.ru",
    "ok.ru", "mycdn.me", "okcdn.ru", "odkl.ru",
    "ozon.ru", "ozon.com", "ozone.ru", "wildberries.ru", "wb.ru", "wbbasket.ru",
    "dns-shop.ru", "citilink.ru", "mts.ru", "reg.ru", "2ip.ru",
    "donationalerts.com", "boosty.to", "habr.com",
    # инфраструктура, которую десинк ломает без всякой пользы
    "microsoft.com", "microsoftonline.com", "live.com", "sharepoint.com",
    "nvidia.com", "msi.com", "akamaitechnologies.com",
    "marketplace.visualstudio.com", "vsassets.io",
] + ANTICHEAT_DOMAINS

# Старые категории -> новые группы. Нужно ровно один релиз: чтобы у тех, кто
# обновился, сохранились галочки, а откат на прошлую сборку ничего не сломал.
LEGACY_MAP: Dict[str, List[str]] = {
    "Игры": ["epic", "steam", "riot", "blizzard", "games"],
    "Игровые сети / CDN": ["cdn"],
    "Discord": ["discord"],
    "Telegram": ["telegram"],
    "Нейросети (AI)": ["ai"],
    "Стриминг / видео": ["youtube", "twitch"],
}


def title(gid: str) -> str:
    g = GROUPS.get(gid)
    return g["title"] if g else gid


def probe_hosts(gid: str) -> List[str]:
    g = GROUPS.get(gid)
    return list(g.get("probe", [])) if g else []


def udp_range(gid: str) -> Optional[list]:
    """Диапазоны не-QUIC UDP группы: [(порт_от, порт_до), …] либо None."""
    g = GROUPS.get(gid)
    if not g:
        return None
    span = g.get("udp")
    if not span:
        return None
    # допускаем и один диапазон кортежем, и список диапазонов
    return list(span) if isinstance(span, list) else [tuple(span)]


def all_domains() -> List[str]:
    seen: List[str] = []
    for g in GROUPS.values():
        for d in g["domains"]:
            if d not in seen:
                seen.append(d)
    return seen


def domains_for(group_ids) -> set:
    out = set()
    for gid in group_ids:
        g = GROUPS.get(gid)
        if g:
            out.update(g["domains"])
    return out


def host_group_map(group_ids) -> Dict[str, str]:
    """{домен: id группы} для включённых групп.

    Домен, попавший в две группы, остаётся за первой по порядку GROUPS —
    порядок здесь идёт от частного к общему (epic/steam/… раньше games/cdn).
    """
    out: Dict[str, str] = {}
    wanted = set(group_ids)
    for gid, g in GROUPS.items():
        if gid not in wanted:
            continue
        for d in g["domains"]:
            out.setdefault(d, gid)
    return out


def migrate_categories(old: dict) -> Dict[str, bool]:
    """Старый словарь {категория: вкл} -> {группа: вкл}."""
    out = {gid: True for gid in GROUPS}
    if not old:
        return out
    for cat, on in old.items():
        for gid in LEGACY_MAP.get(cat, []):
            out[gid] = bool(on)
    return out


def to_legacy_categories(groups: dict) -> Dict[str, bool]:
    """Обратная проекция — чтобы старая сборка прочитала настройки и не упала."""
    out: Dict[str, bool] = {}
    for cat, gids in LEGACY_MAP.items():
        out[cat] = any(groups.get(g, True) for g in gids)
    return out


# Совместимость со старым кодом (rufreedom.py, генерация config/hostlist.txt).
SERVICES: Dict[str, List[str]] = {
    cat: sorted(domains_for(gids)) for cat, gids in LEGACY_MAP.items()
}
