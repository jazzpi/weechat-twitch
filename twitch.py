# -*- coding: utf-8 -*-
#
# twitch.py
# Copyright (c) 2016 jazzpi <jasper@mezzo.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

SCRIPT_NAME = 'twitch'
SCRIPT_AUTHOR = 'jazzpi'
SCRIPT_VERSION = '0.1.0'
SCRIPT_LICENSE = 'MIT'
SCRIPT_DESC = 'Makes WeeChat work with Twitch'

twitch_settings_default = {
    'twitch_server': (
        'twitch',
        'The name of the server that connects to Twitch.TV'),
    'group_server': (
        'twitch-group',
        'The name of the server that connects to the Group Chat'),
    'user_prefix': (
        '',
        "The prefix in front of a standard user's name"),
    'user_prefix_color': (
        '',
        "The color of the prefix in front of a standard user's name. "
        "Empty for default chat color."),
    'sub_prefix': (
        '%',
        "The prefix in front of a channel subscriber's name"),
    'sub_prefix_color': (
        'white',
        "The color of the prefix in front of a channel subscriber's name. "
        "Empty for default chat color."),
    'turbo_prefix': (
        '+',
        "The prefix in front of a turbo user's name"),
    'turbo_prefix_color': (
        'white,61',
        "The color of the prefix in front of a turbo user's name. "
        "Empty for default chat color."),
    'mod_prefix': (
        '@',
        "The prefix in front of a channel moderator's name"),
    'mod_prefix_color': (
        'white,70',
        "The color of the prefix in front of a channel moderator's name. "
        "Empty for default chat color."),
    'broadcaster_prefix': (
        '~',
        "The prefix in front of a broadcaster's name"),
    'broadcaster_prefix_color': (
        'white,160',
        "The color of the prefix in front of a broadcaster's name. "
        "Empty for default chat color."),
    'global_mod_prefix': (
        '*',
        "The prefix in front of a global moderator's name"),
    'global_mod_prefix_color': (
        'white,22',
        "The color of the prefix in front of a global moderator's name. "
        "Empty for default chat color."),
    'staff_prefix': (
        '&',
        "The prefix in front of a staff member's name"),
    'staff_prefix_color': (
        'white,17',
        "The color of the prefix in front of a staff member's name. "
        "Empty for default chat color."),
    'admin_prefix': (
        '!',
        "The prefix in front of an admin's name"),
    'admin_prefix_color': (
        'white,214',
        "The prefix in front of an admin's name."
        "Empty for default chat color.")
}
twitch_settings = {}
buffers = {}
user_self = {'name': '', 'color': 'chat', 'display_name': '', 'channels': {}}
users = {}
color_messages = {}
outgoing_messages = []
message_count = 0

import_ok = True

try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat.')
    print('Get WeeChat now at: http://weechat.org/')
    import_ok = False
try:
    import time
except:
    print('Error while trying to import time module')
    import_ok = False


def get_name(nick):
    """Get the best guess at a user's name we have"""
    user = users.get(nick.lower(), {'display_name': nick})
    display_name = user['display_name']
    if display_name == '':
        display_name = user['name']
    if display_name == '':
        display_name = nick
    return display_name


def prefix_for_user_type(user_type):
    """Get a colored prefix for a given user type"""
    prefix = weechat.color(twitch_settings[user_type + '_prefix_color']) + \
        twitch_settings[user_type + '_prefix'] + weechat.color('chat')
    return prefix


def prefix_for_user(channel, user):
    """
    Gets the prefix (list of prefixes for user types) for a user in a channel
    """
    channel_tags = user['channels'].get(channel, {})
    prefix = prefix_for_user_type(channel_tags.get('user_type', 'user'))
    if channel_tags.get('mod'):
        prefix += prefix_for_user_type('mod')
    if user.get('turbo'):
        prefix += prefix_for_user_type('turbo')
    if channel_tags.get('subscriber'):
        prefix += prefix_for_user_type('sub')
    return prefix


def update_user(nick, user_tags, channel='', channel_tags={}):
    """Update properties for a user or create it if it doesn't exist"""
    nick = nick.lower()
    if nick in users:
        users[nick].update(user_tags)
    else:
        users[nick] = user_tags
        users[nick]['channels'] = {}
    if channel != '':
        channel_dict = users[nick]['channels'].get(channel, {
                'mod': False,
                'subscriber': False,
                'user_type': 'user'
            })
        channel_dict.update(channel_tags)
        if '#' + nick == channel:
            channel_dict['user_type'] = 'broadcaster'
        users[nick]['channels'][channel] = channel_dict


def parse_tags(tags_string):
    """Parse IRCv3 tags as used by Twitch.TV"""
    if tags_string == '':
        return {}, {}
    tags = {}
    user_tags = {'display_name': '', 'name': ''}
    split = tags_string.split(';')
    for i, tag in enumerate(split):
        split2 = tag.split('=', 1)
        if len(split2) == 1:
            if split2 != '':
                tags[split2[0]] = True
            continue
        key, value = split2
        value = value.replace('\\:', ';')
        value = value.replace('\\s', ' ')
        value = value.replace('\\n', '\n')
        value = value.replace('\\r', '\r')
        value = value.replace('\\\\', '\\')
        value = value or None
        tags[key] = value
    if 'display-name' in tags:
        user_tags['display_name'] = tags['display-name']
        user_tags['name'] = tags['display-name'].lower()
    if 'color' in tags and tags['color'] is not None:
        user_tags['color'] = rgb2short(tags['color'])
    if 'turbo' in tags:
        user_tags['turbo'] = bool(int(tags['turbo']))
    channel_tags = {}
    for key in ('mod', 'subscriber'):
        if key in tags:
            channel_tags[key] = bool(int(tags[key]))  # '0' = False, '1' = True
    return tags, user_tags, channel_tags


def get_buffer(nick, overwrite_name=False):
    """Get the buffer for a nick or create it if it doesn't exist"""
    buffer = buffers.get(nick.lower())
    name = get_name(nick)
    if buffer is None:
        buffer = weechat.buffer_new(
            'TWITCH-WHISPER.' + name,
            'handle_whisper_buffer_input', name,
            'handle_whisper_buffer_close', name)
        weechat.buffer_set(buffer, 'short_name', name)
        buffers[nick.lower()] = buffer
    elif overwrite_name:
        weechat.buffer_set(buffer, 'short_name', nick)
    return buffer


def prnt_message(channel, nick, message):
    """Prints a message with proper colors and prefixes"""
    user = users[nick]
    prefix = prefix_for_user(channel, user)
    color = user.get('color')
    if color is None:
        color = weechat.info_get('irc_nick_color_name', user['display_name'])
    buffer = weechat.info_get('irc_buffer', twitch_settings['twitch_server'] +
                              ',' + channel)
    full_message = '{}{}{}{}\t{}'.format(
        prefix, weechat.color(color), user['display_name'],
        weechat.color('chat'), message)
    weechat.prnt_date_tags(
        buffer, 0, 'irc_privmsg,notify_message,prefix_nick_{0},nick_{1},'
        'host_{1}@{1}.tmi.twitch.tv,log1'.format(color, nick),
        full_message)
    return buffer


def handle_whisper_buffer_close(data, buffer):
    """Handles a closing buffer for a nick (data)."""
    buffers.pop(data.lower())
    return weechat.WEECHAT_RC_OK


def handle_whisper_buffer_input(data, buffer, input_data):
    """Handles input in a buffer for a nick (data)."""
    weechat.command('',
                    '/msg -server {} jtv .w {} {}'.format(
                        twitch_settings['group_server'], data, input_data))
    weechat.prnt(buffer, user_self['display_name'] + '\t' + input_data)
    current = weechat.current_buffer()
    italic = weechat.color('/chat')
    if buffer != current:
        name = get_name(data)
        weechat.prnt(current, '{}You whisper to {}: {}'.format(italic, name,
                                                               input_data))
    return weechat.WEECHAT_RC_OK


def handle_whisper(data, modifier, modifier_data, string):
    """Handle a WHISPER command"""
    if modifier_data != twitch_settings['group_server']:
        return string
    parsed = weechat.info_get_hashtable('irc_message_parse',
                                        {"message": string})
    # Channel tags are empty here since whispers aren't bound to a channel
    tags, user_tags, _ = parse_tags(parsed['tags'])
    nick = parsed['nick']
    update_user(nick, user_tags)
    name = get_name(nick)
    msg = parsed['text']
    buffer = get_buffer(name, True)
    italic = weechat.color('/' + users[nick]['color'])
    color = weechat.color(users[nick]['color'])
    default_color = weechat.color('chat')
    weechat.prnt_date_tags(
        buffer, int(time.time()), 'notify_private',
        '{}{}{}\t{}'.format(color, name, default_color, msg))
    current = weechat.current_buffer()
    if buffer != current:
        weechat.prnt(current, '{}{} whispers: {}'.format(italic, name, msg))
    # Return '' so WeeChat doesn't get all confused trying to parse a whisper
    return ''


def handle_globaluserstate(data, modifier, modifier_data, string):
    """Handles a GLOBALUSERSTATE"""
    if modifier_data not in (twitch_settings['twitch_server'],
                             twitch_settings['group_server']):
        return string
    parsed = weechat.info_get_hashtable('irc_message_parse',
                                        {"message": string})
    # All we're interested in are user tags
    update_user(users_self['name'], parse_tags(parsed['tags'])[1])
    return ''


def handle_userstate(data, modifier, modifier_data, string):
    """Handles a USERSTATE"""
    if modifier_data not in (twitch_settings['twitch_server'],
                             twitch_settings['group_server']):
        return string
    parsed = weechat.info_get_hashtable('irc_message_parse',
                                        {"message": string})
    # We're not interested in tags like emote-set etc.
    _, user_tags, channel_tags = parse_tags(parsed['tags'])
    update_user(user_self['name'], user_tags, parsed['text'], channel_tags)
    return ''


def handle_roomstate(data, modifier, modifier_data, string):
    """Handles a ROOMSTATE"""
    if modifier_data not in (twitch_settings['twitch_server'],
                             twitch_settings['group_server']):
        return string
    return ''


def handle_privmsg(data, modifier, modifier_data, string):
    """Handle a PRIVMSG"""
    if modifier_data != 'twitch':
        return string
    parsed = weechat.info_get_hashtable('irc_message_parse',
                                        {"message": string})
    # We're not interested in tags like emote-set etc.
    _, user_tags, channel_tags = parse_tags(parsed['tags'])
    channel = parsed['channel']
    nick = parsed['nick']
    update_user(nick, user_tags, channel, channel_tags)
    prnt_message(channel, nick, parsed['text'])
    return ''


def handle_config_change(data, option, value):
    """Handle a config change"""
    pos = option.rfind('.')
    if pos > 0:
        name = option[pos+1:]
        if name in twitch_settings:
            twitch_settings[name] = value
    return weechat.WEECHAT_RC_OK


def handle_whisper_command(data, buffer, args):
    """Handles a /whisper command"""
    split = args.split(' ', 1)
    if len(split) < 2:
        return weechat.WEECHAT_RC_ERROR
    buffer = get_buffer(split[0])
    return handle_whisper_buffer_input(split[0], buffer, split[1])


def handle_w_command(data, buffer, args):
    """Handles a /w command"""
    server = weechat.buffer_get_string(buffer, 'localvar_server')
    if server in (twitch_settings['twitch_server'],
                  twitch_settings['group_server']):
        return handle_whisper_command(data, buffer, args)
    else:
        return weechat.command(buffer, '/who ' + args)


def handle_irc_out1_privmsg(data, modifier, modifier_data, string):
    """Handle an outgoing PRIVMSG message"""
    if modifier_data != twitch_settings['twitch_server']:
        return string
    global message_count
    message_count += 1
    if message_count > 10:
        return
    try:
        outgoing_messages.remove(string)
    except ValueError:
        pass
    else:
        return string
    outgoing_messages.append(string)
    parsed = weechat.info_get_hashtable('irc_message_parse',
                                        {'message': string})
    buffer = prnt_message(parsed['channel'], user_self['name'], parsed['text'])
    weechat.command(buffer, '/quote -server {} PRIVMSG {} :{}'.format(
        twitch_settings['twitch_server'], parsed['channel'], parsed['text']))
    return ''


def handle_irc_out1_pass(data, modifier, modifier_data, string):
    """Handle an outgoing PASS message"""
    if modifier_data in (twitch_settings['twitch_server'],
                         twitch_settings['group_server']):
        return ('CAP REQ :twitch.tv/commands twitch.tv/tags '
                'twitch.tv/membership\r\n' + string)
    return string

if __name__ == '__main__' and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
                        SCRIPT_LICENSE, SCRIPT_DESC, '', ''):
        # Set/get settings
        version = weechat.info_get('version_number', '') or 0
        for option, value in twitch_settings_default.items():
            if weechat.config_is_set_plugin(option):
                twitch_settings[option] = weechat.config_get_plugin(option)
            else:
                weechat.config_set_plugin(option, value[0])
                twitch_settings[option] = value[0]
            if int(version) >= 0x00030500:
                weechat.config_set_desc_plugin(
                    option,
                    value[1] + ' ( default: ' + value[0] + ')')
        user_self['name'] = weechat.config_string(weechat.config_get(
            'irc.server.' + twitch_settings['group_server'] + '.nicks')
            ).split(',', 1)[0]
        user_self['display_name'] = user_self['name']
        user_self['color'] = weechat.config_string(
            weechat.config_get('weechat.color.chat_nick_self'))
        user_self['channels']['#' + user_self['name']] = {
            'user_type': 'broadcaster'
        }
        users[user_self['name']] = user_self

        # Detect config changes
        weechat.hook_config('plugins.var.python.' + SCRIPT_NAME + '.*',
                            'handle_config_change', '')

        weechat.hook_modifier('irc_in_whisper', 'handle_whisper', '')
        weechat.hook_modifier('irc_in_globaluserstate',
                              'handle_globaluserstate', '')
        weechat.hook_modifier('irc_in_userstate', 'handle_userstate', '')
        weechat.hook_modifier('irc_in_roomstate', 'handle_roomstate', '')
        # Signals don't work because it doesn't send tags
        weechat.hook_modifier('irc_in_privmsg', 'handle_privmsg', 'twitch')
        weechat.hook_command('3000|whisper',
                             'Send a Twitch.TV whisper to a user',
                             '<user> <message>',
                             '   user: Send to this user\n'
                             'message: Send this message',
                             '%(irc_server_nicks)',
                             'handle_whisper_command',
                             '')
        weechat.hook_command('whisper_check_server',
                             'Send a Twitch.TV whisper to a user only if run '
                             ' from a Twitch.TV server, else /who - use /w '
                             'instead. See /help whisper',
                             '<user> <message> || [<mask> [o]]',
                             '   user: Send to this user\n'
                             'message: Send this message\n'
                             '   mask: Query only information which match this'
                             ' mask\n'
                             '      o: Only operators are returned according '
                             'to the mask supplied',
                             '%(irc_server_nicks)',
                             'handle_w_command',
                             '')
        weechat.command('', '/alias del w')
        weechat.command('', '/alias add w /whisper_check_server')
        # Hook this with a very high priority because we'll send it
        # again and other hooks should only see it once
        weechat.hook_modifier('99999|irc_out1_privmsg',
                              'handle_irc_out1_privmsg', '')
        weechat.hook_modifier('irc_out1_pass', 'handle_irc_out1_pass', '')

# This look-up table and the rgb2short function were taken from Micah Elliott
# at https://gist.github.com/MicahElliott/719710 and modified slightly
CLUT = {  # color look-up table
    # Primary 3-bit (8 colors). Unique representation!
    '000000':  '00',
    '800000':  '01',
    '008000':  '02',
    '808000':  '03',
    '000080':  '04',
    '800080':  '05',
    '008080':  '06',
    'c0c0c0':  '07',

    # Equivalent "bright" versions of original 8 colors.
    '808080':  '08',
    'ff0000':  '09',
    '00ff00':  '10',
    'ffff00':  '11',
    '0000ff':  '12',
    'ff00ff':  '13',
    '00ffff':  '14',
    'ffffff':  '15',

    # Strictly ascending.
    '000000':  '16',
    '00005f':  '17',
    '000087':  '18',
    '0000af':  '19',
    '0000d7':  '20',
    '0000ff':  '21',
    '005f00':  '22',
    '005f5f':  '23',
    '005f87':  '24',
    '005faf':  '25',
    '005fd7':  '26',
    '005fff':  '27',
    '008700':  '28',
    '00875f':  '29',
    '008787':  '30',
    '0087af':  '31',
    '0087d7':  '32',
    '0087ff':  '33',
    '00af00':  '34',
    '00af5f':  '35',
    '00af87':  '36',
    '00afaf':  '37',
    '00afd7':  '38',
    '00afff':  '39',
    '00d700':  '40',
    '00d75f':  '41',
    '00d787':  '42',
    '00d7af':  '43',
    '00d7d7':  '44',
    '00d7ff':  '45',
    '00ff00':  '46',
    '00ff5f':  '47',
    '00ff87':  '48',
    '00ffaf':  '49',
    '00ffd7':  '50',
    '00ffff':  '51',
    '5f0000':  '52',
    '5f005f':  '53',
    '5f0087':  '54',
    '5f00af':  '55',
    '5f00d7':  '56',
    '5f00ff':  '57',
    '5f5f00':  '58',
    '5f5f5f':  '59',
    '5f5f87':  '60',
    '5f5faf':  '61',
    '5f5fd7':  '62',
    '5f5fff':  '63',
    '5f8700':  '64',
    '5f875f':  '65',
    '5f8787':  '66',
    '5f87af':  '67',
    '5f87d7':  '68',
    '5f87ff':  '69',
    '5faf00':  '70',
    '5faf5f':  '71',
    '5faf87':  '72',
    '5fafaf':  '73',
    '5fafd7':  '74',
    '5fafff':  '75',
    '5fd700':  '76',
    '5fd75f':  '77',
    '5fd787':  '78',
    '5fd7af':  '79',
    '5fd7d7':  '80',
    '5fd7ff':  '81',
    '5fff00':  '82',
    '5fff5f':  '83',
    '5fff87':  '84',
    '5fffaf':  '85',
    '5fffd7':  '86',
    '5fffff':  '87',
    '870000':  '88',
    '87005f':  '89',
    '870087':  '90',
    '8700af':  '91',
    '8700d7':  '92',
    '8700ff':  '93',
    '875f00':  '94',
    '875f5f':  '95',
    '875f87':  '96',
    '875faf':  '97',
    '875fd7':  '98',
    '875fff':  '99',
    '878700': '100',
    '87875f': '101',
    '878787': '102',
    '8787af': '103',
    '8787d7': '104',
    '8787ff': '105',
    '87af00': '106',
    '87af5f': '107',
    '87af87': '108',
    '87afaf': '109',
    '87afd7': '110',
    '87afff': '111',
    '87d700': '112',
    '87d75f': '113',
    '87d787': '114',
    '87d7af': '115',
    '87d7d7': '116',
    '87d7ff': '117',
    '87ff00': '118',
    '87ff5f': '119',
    '87ff87': '120',
    '87ffaf': '121',
    '87ffd7': '122',
    '87ffff': '123',
    'af0000': '124',
    'af005f': '125',
    'af0087': '126',
    'af00af': '127',
    'af00d7': '128',
    'af00ff': '129',
    'af5f00': '130',
    'af5f5f': '131',
    'af5f87': '132',
    'af5faf': '133',
    'af5fd7': '134',
    'af5fff': '135',
    'af8700': '136',
    'af875f': '137',
    'af8787': '138',
    'af87af': '139',
    'af87d7': '140',
    'af87ff': '141',
    'afaf00': '142',
    'afaf5f': '143',
    'afaf87': '144',
    'afafaf': '145',
    'afafd7': '146',
    'afafff': '147',
    'afd700': '148',
    'afd75f': '149',
    'afd787': '150',
    'afd7af': '151',
    'afd7d7': '152',
    'afd7ff': '153',
    'afff00': '154',
    'afff5f': '155',
    'afff87': '156',
    'afffaf': '157',
    'afffd7': '158',
    'afffff': '159',
    'd70000': '160',
    'd7005f': '161',
    'd70087': '162',
    'd700af': '163',
    'd700d7': '164',
    'd700ff': '165',
    'd75f00': '166',
    'd75f5f': '167',
    'd75f87': '168',
    'd75faf': '169',
    'd75fd7': '170',
    'd75fff': '171',
    'd78700': '172',
    'd7875f': '173',
    'd78787': '174',
    'd787af': '175',
    'd787d7': '176',
    'd787ff': '177',
    'd7af00': '178',
    'd7af5f': '179',
    'd7af87': '180',
    'd7afaf': '181',
    'd7afd7': '182',
    'd7afff': '183',
    'd7d700': '184',
    'd7d75f': '185',
    'd7d787': '186',
    'd7d7af': '187',
    'd7d7d7': '188',
    'd7d7ff': '189',
    'd7ff00': '190',
    'd7ff5f': '191',
    'd7ff87': '192',
    'd7ffaf': '193',
    'd7ffd7': '194',
    'd7ffff': '195',
    'ff0000': '196',
    'ff005f': '197',
    'ff0087': '198',
    'ff00af': '199',
    'ff00d7': '200',
    'ff00ff': '201',
    'ff5f00': '202',
    'ff5f5f': '203',
    'ff5f87': '204',
    'ff5faf': '205',
    'ff5fd7': '206',
    'ff5fff': '207',
    'ff8700': '208',
    'ff875f': '209',
    'ff8787': '210',
    'ff87af': '211',
    'ff87d7': '212',
    'ff87ff': '213',
    'ffaf00': '214',
    'ffaf5f': '215',
    'ffaf87': '216',
    'ffafaf': '217',
    'ffafd7': '218',
    'ffafff': '219',
    'ffd700': '220',
    'ffd75f': '221',
    'ffd787': '222',
    'ffd7af': '223',
    'ffd7d7': '224',
    'ffd7ff': '225',
    'ffff00': '226',
    'ffff5f': '227',
    'ffff87': '228',
    'ffffaf': '229',
    'ffffd7': '230',
    'ffffff': '231',

    # Gray-scale range.
    '080808': '232',
    '121212': '233',
    '1c1c1c': '234',
    '262626': '235',
    '303030': '236',
    '3a3a3a': '237',
    '444444': '238',
    '4e4e4e': '239',
    '585858': '240',
    '626262': '241',
    '6c6c6c': '242',
    '767676': '243',
    '808080': '244',
    '8a8a8a': '245',
    '949494': '246',
    '9e9e9e': '247',
    'a8a8a8': '248',
    'b2b2b2': '249',
    'bcbcbc': '250',
    'c6c6c6': '251',
    'd0d0d0': '252',
    'dadada': '253',
    'e4e4e4': '254',
    'eeeeee': '255',
}


def rgb2short(rgb):
    """Find the closest xterm-256 approximation to the given RGB value."""
    rgb = rgb.lstrip('#')
    incs = (0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff)
    # Break 6-char RGB code into 3 integer vals.
    parts = [int(h, 16) for h in (rgb[0:2], rgb[2:4], rgb[4:6])]
    res = []
    for part in parts:
        i = 0
        while i < len(incs)-1:
            s, b = incs[i], incs[i+1]  # smaller, bigger
            if s <= part <= b:
                s1 = abs(s - part)
                b1 = abs(b - part)
                if s1 < b1:
                    closest = s
                else:
                    closest = b
                res.append(closest)
                break
            i += 1
    res = ''.join([('%02.x' % i) for i in res])
    equiv = CLUT[res]
    return equiv
