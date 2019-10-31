import requests, json
import telebot
import re

bot_token = "" # insert your telegram bot token
bot = telebot.TeleBot(bot_token)
API_KEY = '' # insert your API key VirusTotal
virus_total_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
url_input = ""


# keyboard1 = telebot.types.ReplyKeyboardMarkup()
# keyboard1.row('Start', 'Help')

@bot.message_handler(commands=['start'])
def start_message(message):
    bot.send_message(message.chat.id, 'Enter url to scan')


@bot.message_handler(content_types=['text'])
def msg(message):
    user_url_input = message.text
    pattern = "^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
    if re.findall(pattern, user_url_input):
        params = {'apikey': API_KEY, 'url': user_url_input}
        virustotal_response = requests.post(virus_total_url, data=params, verify=False)
        scan_id = virustotal_response.json()['scan_id']
        url_scan_id = scan_id[0:64]
        url_virus_check_result = "https://www.virustotal.com/ui/urls/{}?relationships=last_serving_ip_address,network_location".format(
            url_scan_id)
        is_report_valid = virustotal_response.json()['response_code'] == 1
        if is_report_valid:
            print_report_scan(message.chat.id, virustotal_response, url_virus_check_result)
        else:
            bot.send_message(message.chat.id, virustotal_response.json()['verbose_msg'])
    else:
        bot.send_message(message.chat.id, "Invalid URL, try again")


def print_report_scan(response_chat_id, response_virustotal, url_virus_check_result):
    antiviruses_report_full = requests.get(url_virus_check_result)
    antiviruses_current = antiviruses_report_full.json()['data']['attributes']['last_analysis_results']
    kasp_res = antiviruses_current['Kaspersky']['result']
    eset_res = antiviruses_current['ESET']['result']
    yandex_sb = antiviruses_current['Yandex Safebrowsing'][
        'result']
    bot.send_message(response_chat_id,
                     "Report from virustotal: {}".format(response_virustotal.json()['permalink']))
    bot.send_message(response_chat_id,
                     "Result top AV: Kaspersky: {}, ESET: {}, Yandex SB: {}".format(kasp_res, eset_res,
                                                                                    yandex_sb))
    count_clean = 0
    count_unrated = 0
    count_virus = 0
    for i in antiviruses_current:
        if antiviruses_current[i]['result'] == "clean":
            count_clean += 1
        elif antiviruses_current[i]['result'] == "unrated":
            count_unrated += 1
        else:
            count_virus += 1
    count = len(antiviruses_current)
    result_end = "{}/{}".format(count_virus, count)
    bot.send_message(response_chat_id, "Result scan: {}".format(result_end))


@bot.message_handler(
    content_types=['sticker', 'contact', 'location', 'venue', 'userprofilephotos', 'voice', 'audio', 'video', 'photo'])
def sticker_handler(message):
    bot.send_message(message.chat.id, "Sorry, I can not handle this type of file")


@bot.message_handler(content_types=['document'])
def file_handler(message):
    url_file_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
    params_scan_file = {'apikey': API_KEY}
    file_upload_id = bot.get_file(message.document.file_id)  # определяем id Загруженного файла
    url_upload_file = "https://api.telegram.org/file/bot{}/{}".format(bot_token,
                                                                      file_upload_id.file_path)  # url for download file
    recvfile = requests.get(url_upload_file)
    files = {"file": recvfile.content}

    response_file_scan = requests.post(url_file_scan, files=files,
                                       params=params_scan_file)  # отправляем файлы на virustotal
    if response_file_scan.json()['response_code'] == 1:

        bot.send_message(message.chat.id, "Report from virustotal: {}".format(response_file_scan.json()['permalink']))

        scan_file_id = response_file_scan.json()['scan_id']
        url_scan_file_id = scan_file_id[0:64]
        url_virus_check_file_result = "https://www.virustotal.com/ui/files/{}".format(url_scan_file_id)
        antiviruses_report_file_full = requests.get(url_virus_check_file_result)
        antiviruses_report_file_full_json = antiviruses_report_file_full.json()['data']['attributes'][
            'last_analysis_results']
        kasp_res = antiviruses_report_file_full_json['Kaspersky']['result']
        McAfee_res = antiviruses_report_file_full_json['McAfee']['result']
        yandex_res = antiviruses_report_file_full_json['Yandex']['result']
        bot.send_message(message.chat.id,
                         "Result top AV: Kaspersky: {}, McAfee: {}, Yandex: {}".format(kasp_res, McAfee_res,
                                                                                       yandex_res))
        count_clean = 0
        count_virus = 0
        for i in antiviruses_report_file_full_json:
            if not antiviruses_report_file_full_json[i]['result']:
                count_clean += 1
            elif antiviruses_report_file_full_json[i]['result'] == "Unsafe":
                count_clean += 1
            else:
                count_virus += 1
        print(count_clean)
        count = len(antiviruses_report_file_full_json)
        result_end = "{}/{}".format(count_virus, count)
        bot.send_message(message.chat.id, "Result scan: {}".format(result_end))
    else:
        bot.send_message(message.chat.id, response_file_scan.json()['verbose_msg'])


bot.polling()
