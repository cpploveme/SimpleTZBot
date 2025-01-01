import jwt
import json
import time
import base64
import random
import aiohttp
import asyncio
from hashlib import md5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import os
import copy
import yaml
import pyrogram
from loguru import logger
from pyrogram import Client, filters
from pyrogram.types import BotCommand, Message

version_content = "1.0.2"
version_id = 2024123001
version_source = "Official"

privatekey = "" # base64 编码过的 RSA 私钥
privatekey = base64.b64decode(privatekey)

def sha256_32bytes(data: str, encoding='utf-8'):
    SHA256 = hashes.Hash(hashes.SHA256())
    SHA256.update(data.encode())
    digest = SHA256.finalize().hex()
    output = digest[:32]
    return output.encode(encoding=encoding)

def generate_random_bytes(length: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(length)])

def chacha20_encrypt(plaintext: str, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext

def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def encode_jwt(payload: dict, private_key: str):
    a = jwt.encode(payload, private_key, algorithm="RS512")
    return a

def StrOfSize(size):
    def strofsize(integer, remainder, level):
        if integer >= 1024:
            remainder = integer % 1024
            integer //= 1024
            level += 1
            return strofsize(integer, remainder, level)
        elif integer < 0:
            integer = 0
            return strofsize(integer, remainder, level)
        else:
            return integer, remainder, level

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    integer, remainder, level = strofsize(size, 0, 0)
    if level + 1 > len(units):
        level = -1
    return ('`{}.{:>02d}` {}'.format(integer, remainder, units[level]))

async def send_websocket_request(uri, message, backend_token, name):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(connect=config.config.get('SlaveConfig', {}).get('Timeout', 10))) as session:
            async with session.ws_connect(uri) as ws:
                await ws.send_str(message)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        return msg.data, uri, backend_token, name
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        return None, uri, backend_token, name
    except:
        pass
    return None, uri, backend_token, name

async def sendrequests(data: list):
    tasks = []
    for name in config.config.get('SlaveConfig', {}).get('Slaves', {}):
        uri = config.config['SlaveConfig']['Slaves'][name].get('Address', '')
        token = config.config['SlaveConfig']['Slaves'][name].get('Token', '')
        nonce = generate_random_bytes(16)
        message = {
            "timestamp": int(time.time()),
            "id": bot_me.id,
            "nonce": base64.b64encode(nonce).decode()
        }
        check_content = str(message['timestamp']) + str(message['id']) + str(message['nonce'])
        for content in data:
            if content["type"] == 0:
                continue
            check_content = check_content + content['content']
        check_content = check_content + token
        check = md5()
        check.update(check_content.encode('utf-8'))
        message['token'] = check.hexdigest()
        message['data'] = base64.b64encode(chacha20_encrypt(json.dumps(data), sha256_32bytes(token), nonce)).decode('utf-8')
        message = encode_jwt(message, privatekey)
        task = asyncio.ensure_future(send_websocket_request(uri, message, token, name))
        tasks.append(task)
    result = await asyncio.gather(*tasks)
    return result

async def test_script(code: str):
    results = await sendrequests([{"type": 1, "content": code}])
    resdata = []
    for res in results:
        message, uri, token, name = res
        if message is None:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        message = json.loads(base64.b64decode(message).decode())
        if message.get('error', None) is not None:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message, 'error': message['error']})
            continue
        check_content = str(message['timestamp']) + str(message['version']) + str(message['nonce']) + str(message['data'])
        check_content = check_content + token
        check = md5()
        check.update(check_content.encode('utf-8'))
        try:
            data = json.loads(chacha20_decrypt(base64.b64decode(message['data']), sha256_32bytes(token), base64.b64decode(message['nonce'])))
        except:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        if check.hexdigest() != message['token']:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message, 'data': data})
    return resdata

class Config:
    def __init__(self, configpath="./config.yaml"):
        logger.info('Initializing Config')
        self.config = {}
        try:
            with open(configpath, "r", encoding="UTF-8") as fp:
                self.config = yaml.safe_load(fp)
        except FileNotFoundError:
            logger.error("Config not found")
            os._exit(0)
    
    def reload(self, configpath="./config.yaml"):
        self.config = {}
        try:
            with open(configpath, "r", encoding="UTF-8") as fp:
                self.config = yaml.safe_load(fp)
        except FileNotFoundError:
            logger.error("Config not found")
            os._exit(0)

    def Save(self, configpath="./config.yaml"):
        with open(configpath, "w", encoding="UTF-8") as fp:
            yaml.safe_dump(self.config, fp, sort_keys = False, allow_unicode = True)

    def LoadAdmin(self):
        try:
            logger.info('Obtaining Admin')
            return list(set(self.config['SuAdmin'] + self.config.get('Admin', [])))
        except:
            logger.error("SuAdmin not found")
            os._exit(0)

    def LoadSuAdmin(self):
        try:
            logger.info('Obtaining SuAdmin')
            return self.config['SuAdmin']
        except:
            logger.error("SuAdmin not found")
            os._exit(0)

    def LoadBotToken(self):
        try:
            logger.info('Obtaining Telegram Bot Token')
            return self.config['Bot']['Token']
        except:
            logger.error("Telegram Bot Token not found")
            os._exit(0)
    
    def LoadApiHash(self):
        try:
            logger.info('Obtaining ApiHash')
            return self.config['Bot']['ApiHash']
        except:
            logger.error("ApiHash not found")
            os._exit(0)
    
    def LoadApiId(self):
        try:
            logger.info('Obtaining ApiId')
            return self.config['Bot']['ApiId']
        except:
            logger.error("ApiId not found")
            os._exit(0)

config = Config()

app = Client("Bot", api_id = config.LoadApiId(), api_hash = config.LoadApiHash(), bot_token = config.LoadBotToken())

su_admin_list = config.LoadSuAdmin()

admin_list = config.LoadAdmin()

bot_me = None

async def deletecommand(msg, message, t: int):
    await asyncio.sleep(t)
    try:
        await app.delete_messages(msg.chat.id, msg.id)
    except:
        pass
    try:
        await app.delete_messages(message.chat.id, message.id)
    except:
        pass

@app.on_message(filters.command(['help']))
async def help_bot(client: Client, message: Message):
    logger.info(f"{str(message.from_user.id)} Get Help")
    content = f"欢迎使用 `{bot_me.first_name}` 呢 你可以使用以下指令呢 ~\n\n/help `获取帮助菜单`\n/version `获取版本信息 - {version_content}`\n/stats `获取权限状态`"
    if int(message.from_user.id) in admin_list:
        content = content + """
/info `[管理]查看后端信息`"""
    if int(message.from_user.id) in su_admin_list:
        content = content + """
/grant `[超管]授权一个用户`
/ungrant `[超管]取消用户授权`
/get `[超管]读取配置文件`"""
    msg = await client.send_message(chat_id = message.chat.id, text = content, reply_to_message_id = message.id)
    if not message.chat.type == pyrogram.enums.ChatType.PRIVATE:
        await deletecommand(msg, message, 10)

@app.on_message(filters.command(['version']))
async def get_version(client: Client, message: Message):
    logger.info(f"{str(message.from_user.id)} Get Version")
    cont = f"Version: `{version_content} ({str(version_id)})`\nSource: `{version_source}`"
    msg = await client.send_message(chat_id = message.chat.id, text = cont, reply_to_message_id = message.id)
    await deletecommand(msg, message, 10)

@app.on_message(filters.command(['stats']))
async def get_stats(client: Client, message: Message):
    logger.info(f"{str(message.from_user.id)} Get Stats")
    content = "你当前的权限状态是:\n\n管理权限: "
    if int(message.from_user.id) in admin_list:
        content = content + "✔"
    else:
        content = content + "❌"
    content = content + "\n超管权限: "
    if int(message.from_user.id) in su_admin_list:
        content = content + "✔"
    else:
        content = content + "❌"
    if int(message.from_user.id) in admin_list:
        content = content + "\n\n后端情况: `检测中`"
    msg = await client.send_message(chat_id = message.chat.id, text = content, reply_to_message_id = message.id)
    if int(message.from_user.id) in admin_list:
        results = await sendrequests([{"type": 0}])
        for res in results:
            message, uri, token, name = res
            if message is None:
                content = content + f"`\n{name}`: `掉线`"
            else:
                content = content + f"`\n{name}`: `在线`"
        await client.edit_message_text(chat_id = msg.chat.id, message_id = msg.id, text = content)
    else:
        await deletecommand(msg, message, 10)

@app.on_message(filters.command(['info']))
async def get_info(client: Client, message: Message):
    if not int(message.from_user.id) in admin_list:
        msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 您没有权限呢 请联系超管授权 ~", reply_to_message_id = message.id)
        await deletecommand(msg, message, 10)
        return
    msg = await client.send_message(chat_id = message.chat.id, text = "⏳ 检测中 ~", reply_to_message_id = message.id)
    with open(config.config.get('Script'), 'rb') as f:
        js_code = f.read()
    code = js_code.decode()
    result = await test_script(code)
    content = "🔗 当前后端信息为:"
    for res in result:
        if res['message'] is None:
            content = content + f"\n\n`{res['name']}`: `离线`"
        elif res.get('error', None) is not None:
            content = content + f"\n\n`{res['name']}`: `{res['error']}`"
        else:
            data = json.loads(res['data'])
            content = content + f"\n\n`{res['name']}`:"
            content = content + f"\nCPU: `{data[4]}` %"
            content = content + f"\n下载速度: {StrOfSize(data[0])}/s"
            content = content + f"\n上传速度: {StrOfSize(data[1])}/s"
            content = content + f"\n下载流量: {StrOfSize(data[2])}"
            content = content + f"\n上传流量: {StrOfSize(data[3])}"
    await client.edit_message_text(chat_id = msg.chat.id, message_id = msg.id, text = content)


@app.on_message(filters.command(['grant']))
async def grant(client: Client, message: Message):
    global su_admin_list, admin_list
    if not int(message.from_user.id) in su_admin_list:
        msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 您没有权限呢 请在配置文件中设置呢 ~", reply_to_message_id = message.id)
        await deletecommand(msg, message, 10)
        return
    if message.reply_to_message is not None:
        if message.reply_to_message.from_user.id in su_admin_list:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 对象已经是超管了呢 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
        elif message.reply_to_message.from_user.id in admin_list:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 对象已经是管理员了呢 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
        else:
            config.config['Admin'].append(message.reply_to_message.from_user.id)
            config.Save()
            msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 已将 `{message.reply_to_message.from_user.id}` 授权为管理员 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
    else:
        if len(message.text.split()) >= 2:
            content = ""
            grant_list = []
            for i in message.text.split()[1:]:
                try:
                    i = int(i)
                    if i not in su_admin_list and i not in admin_list:
                        config.config['Admin'].append(i)
                        grant_list.append(i)
                        content = content + "`" + str(i) + "` "
                except:
                    pass
            config.Save()
            su_admin_list = config.LoadSuAdmin()
            admin_list = config.LoadAdmin()
            if len(grant_list) > 0:
                msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 已将 {content} 授权为管理员 ~", reply_to_message_id = message.id)
                await deletecommand(msg, message, 10)
            else:
                msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 没有可授权的id呢 ~", reply_to_message_id = message.id)
                await deletecommand(msg, message, 10)
        else:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 命令格式不对哦 ~ 要这样使用呢: `/grant <可选:id>`", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)

@app.on_message(filters.command(['ungrant']))
async def ungrant(client: Client, message: Message):
    global su_admin_list, admin_list
    if not int(message.from_user.id) in su_admin_list:
        msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 您没有权限呢 请在配置文件中设置呢 ~", reply_to_message_id = message.id)
        await deletecommand(msg, message, 10)
        return
    if message.reply_to_message is not None:
        if message.reply_to_message.from_user.id in su_admin_list:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 对象已经是超管了呢 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
        elif message.reply_to_message.from_user.id not in admin_list:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 对象还不是管理员哦 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
        else:
            config.config['Admin'].remove(message.reply_to_message.from_user.id)
            config.Save()
            msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 已取消 `{message.reply_to_message.from_user.id}` 的授权 ~", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)
    else:
        if len(message.text.split()) >= 2:
            content = ""
            grant_list = []
            for i in message.text.split()[1:]:
                try:
                    i = int(i)
                    if i not in su_admin_list and i in admin_list:
                        config.config['Admin'].remove(i)
                        grant_list.append(i)
                        content = content + "`" + str(i) + "` "
                except:
                    pass
            config.Save()
            su_admin_list = config.LoadSuAdmin()
            admin_list = config.LoadAdmin()
            if len(grant_list) > 0:
                msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 已取消 {content} 的授权 ~", reply_to_message_id = message.id)
                await deletecommand(msg, message, 10)
            else:
                msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 没有可取消授权的id呢 ~", reply_to_message_id = message.id)
                await deletecommand(msg, message, 10)
        else:
            msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 命令格式不对哦 ~ 要这样使用呢: `/ungrant <可选:id>`", reply_to_message_id = message.id)
            await deletecommand(msg, message, 10)

@app.on_message(filters.command(['get']))
async def getting_config(client: Client, message: Message):
    if not int(message.from_user.id) in su_admin_list:
        msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 您没有权限呢 请在配置文件中设置呢 ~", reply_to_message_id = message.id)
        await deletecommand(msg, message, 10)
        return
    try:
        try:
            if message.text.split()[1].split('.')[1] == "ApiId" or message.text.split()[1].split('.')[1] == "ApiHash" or message.text.split()[1].split('.')[1] == "Token":
                msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 获取配置失败\n\n错误: `已屏蔽的路径 {message.text.split()[1].split('.')[0]}`", reply_to_message_id = message.id)
                await deletecommand(msg, message, 10)
                return
        except:
            pass
        data = copy.deepcopy(config.config)
        if len(message.text.split()) == 1:
            data['Bot'].pop("ApiId")
            data['Bot'].pop("ApiHash")
            data['Bot'].pop("Token")
            logger.info(f"Admin {message.from_user.id} Get All Config")
            msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 读取成功啦 ~\n\n键 `全部配置`\n值 `{str(data)}`", reply_to_message_id = message.id)
            await deletecommand(msg, message, 15)
            return
        for item in message.text.split()[1].split('.'):
            data = data[item]
        logger.info(f"SuAdmin {message.from_user.id} Get Config {message.text.split()[1]}")
        msg = await client.send_message(chat_id = message.chat.id, text = f"✔ 读取成功啦 ~\n\n键 `{message.text.split()[1]}`\n值 `{str(data)}`", reply_to_message_id = message.id)
        await deletecommand(msg, message, 15)
    except Exception as e:
        msg = await client.send_message(chat_id = message.chat.id, text = f"❌ 获取配置失败\n\n错误: `{e}`", reply_to_message_id = message.id)
        await deletecommand(msg, message, 10)

async def startcron():
    while True:
        try:
            with open(config.config.get('Script'), 'rb') as f:
                js_code = f.read()
            code = js_code.decode()
            result = await test_script(code)
            content = "🔍 后端报告"
            flag = False
            for res in result:
                temp_flag = False
                temp_content = ""
                if res['message'] is None:
                    temp_content = temp_content + f" 已离线"
                    temp_flag = True
                elif res.get('error', None) is not None:
                    temp_content = temp_content + f"\n错误: `{res['error']}`"
                    temp_flag = True
                else:
                    data = json.loads(res['data'])
                    if data[4] > 90:
                        temp_flag = True
                        temp_content = temp_content + f"\nCPU 已超过 `90` % 当前 `{data[4]}` %"
                    if data[0] < 500 * 1024:
                        temp_flag = True
                        temp_content = temp_content + f"\n下载速度 已低于 `500` KB/s 当前 {StrOfSize(data[0])}/s"
                    if data[1] < 500 * 1024:
                        temp_flag = True
                        temp_content = temp_content + f"\n上传速度 已低于 `500` KB/s 当前 {StrOfSize(data[0])}/s"
                if config.config['SlaveConfig']['Slaves'][res['name']].get('Error', False) == False and temp_flag == True:
                    content = content + f"\n\n后端 `{res['name']}` {temp_content}"
                    flag = True
                config.config['SlaveConfig']['Slaves'][res['name']]['Error'] = temp_flag
            if flag == True:
                await app.send_message(chat_id = config.config.get('Chat', -1), text = content)
            config.Save()
            await asyncio.sleep(config.config.get('CheckInterval', 30))
        except:
            await asyncio.sleep(60)

def main():
    global bot_me
    while True:
        try:
            app.start()
            bot_me = app.get_me()
            loop = asyncio.get_event_loop()
            loop.create_task(startcron())
            app.set_bot_commands([
                BotCommand("help", "获取帮助菜单"), 
                BotCommand("version", f"获取版本信息 - {version_content} ({version_id})"),
                BotCommand("stats", "获取权限状态"),
                BotCommand("info", "查看后端信息"),
            ])
            for admin_id in su_admin_list:
                try:
                    app.send_message(chat_id = admin_id, text = "`Bot` 启动啦 ~")
                except:
                    pass
            logger.info('Bot Start')
            pyrogram.idle()
        except:
            app.stop()
            os._exit(0)

if __name__ == '__main__':
    main()