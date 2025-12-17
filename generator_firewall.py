# ГЕНЕРАТОР ПРАВИЛ FIREWALL С СЕРВИСАМИ И ПОДСЕТЯМИ (FULL MULTITHREADING + BATCH)
import time
import ssl
from xmlrpc.client import ServerProxy, Fault
import ipaddress
import itertools
import random
import datetime
import sys
import json
import os
import io
from tqdm import tqdm
import signal
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    try:
        SCRIPT_DIR = os.getcwd()
    except:
        SCRIPT_DIR = "."
SCRIPT_DIR = os.path.normpath(SCRIPT_DIR)

#--------------------------------------------------------НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ------------------------------------------------------------------------------------------
# ------------- Настройки подключения --------------------
ADDRESS = '10.10.20.81'  # <<< Замените на ваш адрес NGFW >>>
PORT = 4443             # <<< Порт XML-RPC API (4040 → HTTP, 4443 → HTTPS) >>>
LOGIN = 'Admin'         # <<< Логин администратора >>>
PASSWORD = 'Qwerty789'  # <<< Замените на ваш пароль >>>
VERIFY_SSL = False      # <<< True — проверять сертификат (HTTPS), False — отключить проверку (для self-signed) >>>

# --- Параметры задаваемые пользователем ------------
NUM_RULES = 500 # Количество правил, которые нужно создать
NUM_SUBNETS = 35  # Количество подсетей для генерации комбинаций
NUM_SERVICES = 100 # Количество сервисов для создания

# Рекомендуемые параметры для генерация правил Firewall
#+----------------+---------------+---------------+---------------+-----------------+-----------------+-----------------+------------------+
#| Параметр/rules | 1000 rules FW | 3000 rules FW | 5000 rules FW | 10 000 rules FW | 30 000 rules FW | 50 000 rules FW | 100 000 rules FW |
#+----------------+---------------+---------------+---------------+-----------------+-----------------+-----------------+------------------+
#| NUM_RULES      | 1000          | 3000          | 5000          | 10000           | 30000           | 50000           | 100000           |
#| NUM_SUBNETS    | 35            | 55            | 75            | 101             | 175             | 225             | 320              |
#| NUM_SERVICES   | 100           | 150           | 300           | 1000            | 3000            | 4000            | 6000             |
#+----------------+---------------+---------------+---------------+-----------------+-----------------+-----------------+------------------+

# --- Дополнительные параметры работы ------------
BATCH_SIZE = 1000   # Размер группы для создания правил
THREADS_COUNT = 30  # Количество потоков для многопоточности
STARTING_NETWORK_BASE = "10.0.0.0" # Диапазон подсетей для списков

# --- Настройки повторных попыток ---
MAX_RETRIES = 3 # попытки
BASE_DELAY = 1 # секунды
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------


output_buffer = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', write_through=True)
original_stdout = sys.stdout
sys.stdout = output_buffer 

try:
    base_network_ip = ipaddress.IPv4Address(STARTING_NETWORK_BASE)
except ipaddress.AddressValueError as e:
    print(f"[ERROR] Некорректный начальный IP: {e}")
    exit(1)

report_data = {
    "start_time": datetime.datetime.now().isoformat(),
    "parameters": {
        "NUM_RULES": NUM_RULES,
        "NUM_SUBNETS": NUM_SUBNETS,
        "NUM_SERVICES": NUM_SERVICES,
        "BATCH_SIZE": BATCH_SIZE,
        "THREADS_COUNT": THREADS_COUNT,
        "ADDRESS": ADDRESS,
        "PORT": PORT,
        "VERIFY_SSL": VERIFY_SSL,
        "STARTING_NETWORK_BASE": STARTING_NETWORK_BASE
    },
    "objects_created": {
        "services": 0,
        "ip_lists": 0,
        "firewall_rules": 0
    },
    "objects_deleted": {
        "services": 0,
        "ip_lists": 0,
        "firewall_rules": 0
    },
    "errors": [],
    "end_time": None,
    "total_time": None,
    "rollback_performed": False
}

def is_retryable_error(fault):
    if isinstance(fault, Fault):
        code = getattr(fault, 'faultCode', None)
        if code:
            if 500 <= code < 600:
                return True
            if code in [104, 102]:
                 return True
        return False
    return True

def retry_api_call(func, *args, **kwargs):
    last_exception = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < MAX_RETRIES and is_retryable_error(e):
                delay = BASE_DELAY * (2 ** (attempt - 1))
                print(f"[RETRY] Попытка {attempt} не удалась: {e}. Повтор через {delay} сек...")
                time.sleep(delay)
            else:
                print(f"[RETRY] Все {MAX_RETRIES} попыток неудачны. Последняя ошибка: {e}")
                report_data["errors"].append({
                    "type": "API_CALL_FAILURE",
                    "function": func.__name__,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                })
                raise e
    raise last_exception

def create_rpc_client():
    """
    Создаёт XML-RPC клиент с учётом порта и SSL-настроек.
    - Порт 4443 → HTTPS
    - Любой другой порт → HTTP
    - Если VERIFY_SSL=False и используется HTTPS → отключается проверка сертификата
    """
    if PORT == 4443:
        url = f'https://{ADDRESS}:{PORT}/rpc'
        if VERIFY_SSL:
            return ServerProxy(url)
        else:
            context = ssl._create_unverified_context()
            return ServerProxy(url, context=context)
    else:
        url = f'http://{ADDRESS}:{PORT}/rpc'
        return ServerProxy(url)

def get_all_lists_by_type(auth_token, list_type):
    all_lists = {}
    try:
        start = 0
        limit = 1000
        while True:
            result = retry_api_call(server.v2.nlists.list, auth_token, list_type, start, limit, {})
            lists_on_page = result.get('items', [])
            if not lists_on_page:
                break
            for list_info in lists_on_page:
                name = list_info.get('name')
                list_id = list_info.get('id')
                if name and list_id:
                    all_lists[name] = list_id
            count_on_page = len(lists_on_page)
            if count_on_page < limit:
                break
            start += limit
        print(f"[NLISTS] Загружено {len(all_lists)} списков типа '{list_type}'")
        return all_lists
    except Exception as e:
        print(f"[NLISTS] Ошибка получения списков '{list_type}': {e}")
        return {}


def create_single_ip_list_thread(list_params):
    global report_data
    try:
        thread_server = create_rpc_client()
        auth_resp = retry_api_call(thread_server.v2.core.login, LOGIN, PASSWORD, {})
        thread_auth_token = auth_resp['auth_token']
        
        list_info = {'name': list_params['name'], 'type': 'network', 'description': list_params['description']}
        list_id = retry_api_call(thread_server.v2.nlists.add, thread_auth_token, list_info)
        print(f"[NLISTS] Создан список '{list_params['name']}' (ID: {list_id}) в потоке")

        item_info = {'value': list_params['network'], 'description': f"Подсеть {list_params['network']}"}
        item_id = retry_api_call(thread_server.v2.nlists.list.add, thread_auth_token, list_id, item_info)
        print(f"[NLISTS] В список '{list_params['name']}' добавлена подсеть {list_params['network']} в потоке")
        
        return {"success": True, "list_id": list_id, "list_name": list_params['name']}
        
    except Fault as e:
        if e.faultCode == 409:
            print(f"[NLISTS] Список '{list_params['name']}' уже существует (ошибка 409) в потоке.")
            try:
                fresh_lists = get_all_lists_by_type(thread_auth_token, 'network')
                if list_params['name'] in fresh_lists:
                    existing_list_id = fresh_lists[list_params['name']]
                    print(f"[NLISTS] Найден существующий список '{list_params['name']}' (ID: {existing_list_id}) в потоке")
                    return {"success": True, "list_id": existing_list_id, "list_name": list_params['name']}
                else:
                    print(f"[NLISTS] Не удалось найти ID для '{list_params['name']}' после ошибки 409 в потоке.")
                    return {"success": False, "error": "Not found after 409"}
            except Exception as lookup_error:
                print(f"[NLISTS] Ошибка поиска после 409 в потоке: {lookup_error}")
                return {"success": False, "error": str(lookup_error)}
        else:
            print(f"[NLISTS] Ошибка создания списка '{list_params['name']}' в потоке: {e}")
            return {"success": False, "error": str(e)}
    except Exception as e:
        print(f"[NLISTS] Неожиданная ошибка создания списка '{list_params['name']}' в потоке: {e}")
        return {"success": False, "error": str(e)}


def create_single_service_thread(service_params):
    global report_data
    try:
        thread_server = create_rpc_client()
        auth_resp = retry_api_call(thread_server.v2.core.login, LOGIN, PASSWORD, {})
        thread_auth_token = auth_resp['auth_token']
        
        # ПОДГОТОВКА ПРАВИЛЬНОЙ СТРУКТУРЫ NetworkServiceInfo
        service_info = {
            'name': service_params['name'],
            'description': service_params['description'],
            # 'protocols' - это список NetworkServiceProtocolInfo
            'protocols': [
                {
                    'proto': service_params['protocol'], # 'tcp' или 'udp'
                    'port': service_params['dst_port'],  # строка, например "80" или "1000-2000"
                    # 'source_port': service_params.get('src_port', ''), # <-- Опционально, если нужно
                }
            ]
        }
        
        service_id = retry_api_call(thread_server.v1.libraries.service.add, thread_auth_token, service_info)
        print(f"[SERVICES] Создан сервис '{service_params['name']}' (ID: {service_id}, порт: {service_params['dst_port']}) в потоке")
        return {"success": True, "service_id": service_id, "service_name": service_params['name'], "port": service_params['dst_port']}
        
    except Fault as e:
        if e.faultCode == 409:
            print(f"[SERVICES] Сервис с портом {service_params['dst_port']} уже существует (ошибка 409) в потоке, пропускаем...")
            return {"success": True, "skipped": True, "port": service_params['dst_port']} 
        else:
            print(f"[SERVICES] Ошибка создания сервиса {service_params['dst_port']} в потоке: {e}")
            return {"success": False, "error": str(e), "port": service_params['dst_port']}
    except Exception as e:
        print(f"[SERVICES] Неожиданная ошибка создания сервиса {service_params['dst_port']} в потоке: {e}")
        return {"success": False, "error": str(e), "port": service_params['dst_port']}


def create_single_firewall_rule_thread(rule_params):
    global report_data
    try:
        time.sleep(random.uniform(0.001, 0.01))
        
        thread_server = create_rpc_client()
        auth_resp = retry_api_call(thread_server.v2.core.login, LOGIN, PASSWORD, {})
        thread_auth_token = auth_resp['auth_token']
        
        rule_id = retry_api_call(thread_server.v1.firewall.rule.add, thread_auth_token, rule_params)
        print(f"[RULES] Создано правило '{rule_params['name']}' (ID: {rule_id}) в потоке")
        
        return {"success": True, "rule_id": rule_id, "rule_name": rule_params['name']}
        
    except Exception as e:
        print(f"[RULES] Ошибка создания правила '{rule_params['name']}' в потоке: {e}")
        return {"success": False, "error": str(e), "rule_name": rule_params['name']}

try:
    server = create_rpc_client()
    print(f"[API] Подключение к: {ADDRESS}:{PORT} (порт 4443 → HTTPS, иначе HTTP; SSL verify: {VERIFY_SSL})")

    print("[AUTH] Выполнение аутентификации...")
    auth_response = retry_api_call(server.v2.core.login, LOGIN, PASSWORD, {})
    auth_token = auth_response['auth_token']
    print("[AUTH] Аутентификация успешна.")
    
except Exception as e:
    print(f"[ERROR] Ошибка подключения/аутентификации: {e}")
    exit(1)

def main():
    global report_data
    print("=== НАЧАЛО РАБОТЫ ГЕНЕРАТОРА ===")
    
    print("\n--- Шаг 1: Получение существующих списков 'network' ---")
    existing_lists_cache = get_all_lists_by_type(auth_token, 'network')

    print(f"\n--- Шаг 2: Создание IP-списков в {THREADS_COUNT} потоках ---")
    created_lists = []
    list_creation_start_time = time.time()
    
    list_params_batch = []
    for i in range(1, NUM_SUBNETS + 1):
        try:
            ip_int = int(base_network_ip) + (i - 1) * 256
            subnet_ip = ipaddress.IPv4Address(ip_int)
            network_str = f"{subnet_ip}/24"
            list_name = f"AutoGen_Net_{i}_{subnet_ip}"
            
            if list_name in existing_lists_cache:
                print(f"[NLISTS] Список '{list_name}' уже существует (ID: {existing_lists_cache[list_name]})")
                created_lists.append(existing_lists_cache[list_name])
            else:
                list_params_batch.append({
                    'name': list_name,
                    'description': f"Автогенерированный список #{i} для правил FW",
                    'network': network_str
                })
        except Exception as e:
            print(f"[NLISTS] Ошибка при подготовке списка #{i}: {e}")
            report_data["errors"].append({
                "type": "PREPARE_IP_LIST",
                "index": i,
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    if list_params_batch:
        successfully_created_lists = 0
        failed_lists = 0
        
        with ThreadPoolExecutor(max_workers=THREADS_COUNT) as executor, \
             tqdm(total=len(list_params_batch), desc="Создание списков", unit="list", file=sys.stderr) as pbar_lists:
            
            future_to_list_param = {
                executor.submit(create_single_ip_list_thread, list_param): list_param 
                for list_param in list_params_batch
            }
            
            for future in as_completed(future_to_list_param):
                list_param = future_to_list_param[future]
                try:
                    result = future.result()
                    if result["success"]:
                        created_lists.append(result["list_id"])
                        successfully_created_lists += 1
                        existing_lists_cache[result["list_name"]] = result["list_id"]
                    else:
                        failed_lists += 1
                        print(f"[NLISTS] Ошибка создания списка '{list_param['name']}': {result.get('error', 'Unknown error')}")
                except Exception as e:
                    failed_lists += 1
                    print(f"[NLISTS] Необработанная ошибка создания списка '{list_param['name']}': {e}")
                    report_data["errors"].append({
                        "type": "CREATE_IP_LIST_UNHANDLED",
                        "list_name": list_param['name'],
                        "error": str(e),
                        "traceback": traceback.format_exc()
                    })
                pbar_lists.update(1)
        
        print(f"[NLISTS] Создание завершено. Успешно: {successfully_created_lists}, Ошибок: {failed_lists}")

    list_creation_end_time = time.time()
    report_data["objects_created"]["ip_lists"] = len(created_lists)
    print(f"[NLISTS] Всего обработано списков: {len(created_lists)}. Время: {list_creation_end_time - list_creation_start_time:.2f} сек.")

    if len(created_lists) < 2:
        print("[ERROR] Недостаточно списков для правил. Завершение.")
        return

    print(f"\n--- Шаг 3: Создание сервисов в {THREADS_COUNT} потоках ---")
    created_services = []
    services_creation_start_time = time.time()

    existing_ports = set()
    try:
        start_s = 0
        limit_s = 1000
        while True:
            services_result = retry_api_call(server.v1.libraries.services.list, auth_token, start_s, limit_s, {}, [])
            services_page = services_result.get('items', [])
            if not services_page:
                break
            for svc in services_page:
                protocols = svc.get('protocols', [])
                for proto_info in protocols:
                    if proto_info.get('proto') in ['tcp', 'udp']:
                        port_val = proto_info.get('port') # Это dst_port
                        if port_val and port_val != '': 
                            existing_ports.add(port_val)
            if len(services_page) < limit_s:
                break
            start_s += limit_s
        print(f"[SERVICES] Найдено {len(existing_ports)} существующих TCP/UDP dst_port сервисов.")
    except Exception as e:
        print(f"[SERVICES] Ошибка получения существующих сервисов: {e}")

    service_params_batch = []
    current_port = 2000
    ports_to_try = 0
    
    while ports_to_try < NUM_SERVICES and current_port < 65535:
        port_str = str(current_port)
        if port_str not in existing_ports:
            service_params_batch.append({
                'name': f'Auto_Service_TCP_{current_port}',
                'description': f'Автосозданный TCP сервис порт {current_port}',
                'protocol': 'tcp',        
                'dst_port': port_str,      
            })
            ports_to_try += 1
        current_port += 1

        if current_port >= 65535:
            print("[SERVICES] Достигнут максимальный номер порта (65535).")
            break

    if service_params_batch:
        successfully_created_services = 0
        failed_services = 0
        skipped_services = 0
        
        with ThreadPoolExecutor(max_workers=THREADS_COUNT) as executor, \
             tqdm(total=len(service_params_batch), desc="Создание сервисов", unit="svc", file=sys.stderr) as pbar_svcs:
            
            future_to_service_param = {
                executor.submit(create_single_service_thread, service_param): service_param 
                for service_param in service_params_batch
            }
            
            for future in as_completed(future_to_service_param):
                service_param = future_to_service_param[future]
                try:
                    result = future.result()
                    if result["success"]:
                        if "skipped" in result:
                            skipped_services += 1
                        else:
                            created_services.append(result["service_id"])
                            successfully_created_services += 1
                            existing_ports.add(result["port"])
                    else:
                        failed_services += 1
                        print(f"[SERVICES] Ошибка создания сервиса '{service_param['name']}': {result.get('error', 'Unknown error')}")
                except Exception as e:
                    failed_services += 1
                    print(f"[SERVICES] Необработанная ошибка создания сервиса '{service_param['name']}': {e}")
                    report_data["errors"].append({
                        "type": "CREATE_SERVICE_UNHANDLED",
                        "service_name": service_param['name'],
                        "error": str(e),
                        "traceback": traceback.format_exc()
                    })
                pbar_svcs.update(1)
        
        print(f"[SERVICES] Создание завершено. Успешно: {successfully_created_services}, Пропущено: {skipped_services}, Ошибок: {failed_services}")

    services_creation_end_time = time.time()
    report_data["objects_created"]["services"] = len(created_services)
    print(f"[SERVICES] Всего создано сервисов: {len(created_services)}. Время: {services_creation_end_time - services_creation_start_time:.2f} сек.")

    if len(created_services) == 0:
        print("[ERROR] Не создано ни одного сервиса. Завершение.")
        return

    print("\n--- Шаг 4: Генерация комбинаций ---")
    all_combinations = list(itertools.permutations(created_lists, 2))
    if len(all_combinations) < NUM_RULES:
        print(f"[WARN] Недостаточно комбинаций ({len(all_combinations)}) для создания {NUM_RULES} правил.")
        print(f"Будет создано только {len(all_combinations)} правил.")
        actual_num_rules = len(all_combinations)
    else:
        actual_num_rules = NUM_RULES

    selected_combinations = all_combinations[:actual_num_rules]
    random.shuffle(selected_combinations)
    print(f"[COMBINATIONS] Подготовлено {len(selected_combinations)} уникальных комбинаций.")

    print("\n--- Шаг 5: Подготовка правил ---")
    prepared_rules = []
    timestamp_suffix = datetime.datetime.now().strftime("%H%M%S")

    for i, (src_list_id, dst_list_id) in enumerate(selected_combinations, start=1):
        selected_service_id = random.choice(created_services)
        rule_name = f"Rule_{i}_{src_list_id}_{dst_list_id}"
        rule_params = {
            'name': rule_name,
            'description': f'Автоматически созданное правило #{i} с IP-списками и сервисом',
            'action': 'drop',
            'src_ips': [['list_id', src_list_id]],
            'dst_ips': [['list_id', dst_list_id]],
            'src_zones': [],
            'dst_zones': [],
            'services': [['service', selected_service_id]],
            'enabled': True,
            'log': False,
            'position_layer': 'local'
        }
        prepared_rules.append(rule_params)
    print(f"[RULES] Подготовлено {len(prepared_rules)} правил.")

    print(f"\n--- Шаг 6: Создание правил в многопоточном режиме ({THREADS_COUNT} потоков) ---")
    rules_created_count = 0
    rules_failed_count = 0
    rules_creation_start_time = time.time()
    
    current_batch_size = BATCH_SIZE
    total_batches = (len(prepared_rules) + current_batch_size - 1) // current_batch_size
    
    batch_num = 0
    while batch_num * current_batch_size < len(prepared_rules):
        batch_number = batch_num + 1
        start_index = batch_num * current_batch_size
        end_index = min(start_index + current_batch_size, len(prepared_rules))
        batch = prepared_rules[start_index:end_index]
        
        try:
            print(f"[RULES] Создание группы правил #{batch_number}/{total_batches} (размер: {len(batch)}) в {THREADS_COUNT} потоках...")
            
            successfully_created_in_batch = 0
            failed_in_batch = 0
            
            with ThreadPoolExecutor(max_workers=THREADS_COUNT) as executor, \
                 tqdm(total=len(batch), desc=f"Группа #{batch_number}", unit="rule", file=sys.stderr, leave=False) as pbar_batch:
                
                future_to_rule_param = {
                    executor.submit(create_single_firewall_rule_thread, rule_param): rule_param 
                    for rule_param in batch
                }
                
                for future in as_completed(future_to_rule_param):
                    rule_param = future_to_rule_param[future]
                    try:
                        result = future.result()
                        if result["success"]:
                            successfully_created_in_batch += 1
                            with threading.Lock(): 
                                report_data["objects_created"]["firewall_rules"] += 1
                        else:
                            failed_in_batch += 1
                            print(f"[RULES] Ошибка создания правила '{rule_param['name']}': {result.get('error', 'Unknown error')}")
                    except Exception as e:
                        failed_in_batch += 1
                        print(f"[RULES] Необработанная ошибка создания правила '{rule_param['name']}': {e}")
                        report_data["errors"].append({
                            "type": "CREATE_RULE_UNHANDLED",
                            "rule_name": rule_param['name'],
                            "error": str(e),
                            "traceback": traceback.format_exc()
                        })
                    pbar_batch.update(1)
            
            rules_created_count += successfully_created_in_batch
            rules_failed_count += failed_in_batch
            print(f"[RULES] Группа #{batch_number}: успешно {successfully_created_in_batch}, ошибок {failed_in_batch}")
            
        except Exception as e:
            print(f"[RULES] Ошибка в группе #{batch_number}, пропуск: {e}")
            rules_failed_count += len(batch)
            
        batch_num += 1
        
    rules_creation_end_time = time.time()
    print(f"[RULES] Создание правил завершено. Успешно: {rules_created_count}, Ошибок: {rules_failed_count}. Время: {rules_creation_end_time - rules_creation_start_time:.2f} сек.")

    print("\n--- Шаг 7: Создание финального правила 'Any_to_Any' ---")
    try:
        final_rule_params = {
            'name': 'Rule_Any_to_Any',
            'description': 'Финальное разрешающее правило',
            'action': 'accept',
            'src_ips': [],
            'dst_ips': [],
            'src_zones': [],
            'dst_zones': [],
            'services': [],
            'enabled': True,
            'log': True,
            'position_layer': 'local'
        }
        final_rule_id = retry_api_call(server.v1.firewall.rule.add, auth_token, final_rule_params)
        print(f"[RULES] Создано финальное правило 'Any_to_Any' (ID: {final_rule_id})")
        report_data["objects_created"]["firewall_rules"] += 1
    except Exception as e:
        print(f"[RULES] Ошибка создания финального правила: {e}")
        report_data["errors"].append({
            "type": "CREATE_FINAL_RULE",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

    total_script_time = time.time() - list_creation_start_time
    print("\n=== ИТОГОВЫЙ ОТЧЕТ ===")
    print(f"Создано сервисов: {report_data['objects_created']['services']}")
    print(f"Создано IP-списков: {report_data['objects_created']['ip_lists']}")
    print(f"Создано правил FW: {report_data['objects_created']['firewall_rules']}")
    print(f"Ошибок: {len(report_data['errors'])}")
    print(f"Общее время: {total_script_time:.2f} сек")

    report_data["end_time"] = datetime.datetime.now().isoformat()
    report_data["total_time"] = total_script_time
    print("=== ЗАВЕРШЕНИЕ РАБОТЫ ГЕНЕРАТОРА ===")

    sys.stdout = original_stdout
    
    try:
        output_buffer.flush()
        underlying_buffer = output_buffer.buffer
        underlying_buffer.seek(0)
        log_content_bytes = underlying_buffer.read()
        log_content = log_content_bytes.decode('utf-8')
        output_buffer.close()
    except Exception as read_error:
        sys.stderr.write(f"\n[LOG] Критическая ошибка при чтении буфера лога: {read_error}\n")
        sys.stderr.flush()
        log_content = "[LOG CONTENT UNAVAILABLE]"
    
    try:
        log_file_path = os.path.join(SCRIPT_DIR, 'api.log')
        log_file_path = os.path.normpath(log_file_path)
        with open(log_file_path, 'w', encoding='utf-8') as log_file:
            log_file.write(log_content)
        print("\n[LOG] Результаты работы записаны в 'api.log'")
    except Exception as e:
        sys.stderr.write(f"\n[LOG] Ошибка записи лога в файл: {e}\n")
        sys.stderr.flush()
    
if __name__ == "__main__":
    main()