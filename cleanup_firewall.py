# ЧИСТИЛЬЩИК СГЕНЕРИРОВАННЫХ ПРАВИЛ FIREWALL С СЕРВИСАМИ И ПОДСЕТЯМИ (FULL MULTITHREADING + TQDM + LOGFILE)
import time
import ssl
from xmlrpc.client import ServerProxy, Fault
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import itertools
from tqdm import tqdm
from io import StringIO
import datetime

#--------------------------------------------------------НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ--------------------------------------------------------------------
# --- Настройки подключения ---
ADDRESS = '10.10.20.10'  # <<< Замените на ваш адрес UTM >>>
PORT = 4040              # <<< Порт XML-RPC API (4040 → HTTP, 4443 → HTTPS) >>>
LOGIN = 'Admin'          # <<< Логин администратора >>>
PASSWORD = '123'   # <<< Замените на ваш пароль >>>
VERIFY_SSL = False       # <<< True — проверять сертификат (HTTPS), False — отключить проверку (для self-signed) >>>

# --- Настройки многопоточности ---
DELETE_THREADS_COUNT = 30  # Количество потоков для многопоточного удаления (default)

# --- Настройки группового удаления ---
BATCH_DELETE_SIZE = 1000    # Размер пакета для группового удаления правил FW (default)

# --- Шаблоны для поиска удаляемых объектов ---
FIREWALL_RULE_NAME_PREFIX = "Rule_"        # Префикс имен правил FW
IP_LIST_NAME_PREFIX = "AutoGen_Net_"       # Префикс имен списков IP
SERVICE_NAME_PREFIX = "Auto_Service_TCP_"  # Префикс имен сервисов
#-------------------------------------------------------------------------------------------------------------------------------------------------

deleted_counters_lock = threading.Lock()
rules_deleted_count_total = 0
services_deleted_count_total = 0
lists_deleted_count_total = 0

thread_auth_cache = threading.local()


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
            return ServerProxy(url, allow_none=True)
        else:
            context = ssl._create_unverified_context()
            return ServerProxy(url, allow_none=True, context=context)
    else:
        url = f'http://{ADDRESS}:{PORT}/rpc'
        return ServerProxy(url, allow_none=True)


def get_thread_auth():
    if not hasattr(thread_auth_cache, 'auth_token'):
        thread_server = create_rpc_client()
        auth_resp = thread_server.v2.core.login(LOGIN, PASSWORD, {})
        thread_auth_cache.auth_token = auth_resp['auth_token']
        thread_auth_cache.server = thread_server
    return thread_auth_cache.auth_token, thread_auth_cache.server

log_buffer = StringIO()
original_stdout = sys.stdout
sys.stdout = log_buffer
try:
    server = create_rpc_client()
    print(f"[INIT] Подключение к API по адресу: {ADDRESS}:{PORT} (порт 4443 → HTTPS, иначе HTTP; SSL verify: {VERIFY_SSL})")

    print("[AUTH] Выполнение аутентификации...")
    auth_response = server.v2.core.login(LOGIN, PASSWORD, {})
    auth_token = auth_response['auth_token']
    print("[AUTH] Аутентификация успешна.")
    
except Exception as e:
    sys.stdout = original_stdout
    print(f"[ERROR] Ошибка подключения или аутентификации: {e}")
    exit(1)

def get_all_firewall_rules(auth_token):
    all_items = []
    start = 0
    limit = 1000
    
    with tqdm(total=100, desc="Подготовка к сбору правил FW", unit="%", file=sys.stderr) as pbar:
        for i in range(100):
            time.sleep(0.01)
            pbar.update(1)
    
    try:
        temp_result = server.v1.firewall.rules.list(auth_token, 0, 1, {})
        total_count = temp_result.get('count', 0)
        
        if total_count == 0:
            print("[FW] Правила FW не найдены")
            return []
    
        while True:
            result = server.v1.firewall.rules.list(auth_token, start, limit, {})
            items_on_page = result.get('items', [])
            
            if not items_on_page:
                break
            
            all_items.extend(items_on_page)
            
            count_on_page = len(items_on_page)
            if count_on_page < limit:
                break
            
            start += limit
            
    except Exception as e:
        print(f"[ERROR] Ошибка при получении правил FW: {e}")
            
    print(f"[FW] Загружено {len(all_items)} правил FW")
    return all_items

def get_all_services(auth_token):
    all_items = []
    start = 0
    limit = 1000
    
    try:
        temp_result = server.v1.libraries.services.list(auth_token, 0, 1, {}, [])
        total_count = temp_result.get('count', 0)
    
        while True:
            result = server.v1.libraries.services.list(auth_token, start, limit, {}, [])
            items_on_page = result.get('items', [])
            
            if not items_on_page:
                break
            
            all_items.extend(items_on_page)
            
            count_on_page = len(items_on_page)
            if count_on_page < limit:
                break
            
            start += limit
            
    except Exception as e:
        print(f"[ERROR] Ошибка при получении сервисов: {e}")
            
    print(f"[SVC] Загружено {len(all_items)} сервисов")
    return all_items

def get_all_nlists(auth_token, list_type):
    all_items = []
    start = 0
    limit = 1000
    
    try:
        temp_result = server.v2.nlists.list(auth_token, list_type, 0, 1, {})
        total_count = temp_result.get('count', 0)
    
        while True:
            result = server.v2.nlists.list(auth_token, list_type, start, limit, {})
            items_on_page = result.get('items', [])
            
            if not items_on_page:
                break
            
            all_items.extend(items_on_page)
            
            count_on_page = len(items_on_page)
            if count_on_page < limit:
                break
            
            start += limit
            
    except Exception as e:
        print(f"[ERROR] Ошибка при получении списков {list_type}: {e}")
            
    print(f"[NL] Загружено {len(all_items)} списков типа '{list_type}'")
    return all_items

def delete_single_firewall_rule_thread(rule_info):
    global rules_deleted_count_total
    rule_id = rule_info['id']
    rule_name = rule_info['name']
    try:
        thread_auth_token, thread_server = get_thread_auth()
        
        thread_server.v1.firewall.rule.delete(thread_auth_token, rule_id)
        
        with deleted_counters_lock:
            rules_deleted_count_total += 1
            
        return True, f"Удалено правило '{rule_name}' (ID: {rule_id})"
        
    except Exception as e:
        return False, f"Ошибка при удалении правила '{rule_name}' (ID: {rule_id}): {e}"

def delete_single_service_thread(service_info):
    global services_deleted_count_total
    service_id = service_info['id']
    service_name = service_info['name']
    try:
        thread_auth_token, thread_server = get_thread_auth()
        
        thread_server.v1.libraries.service.delete(thread_auth_token, service_id)
        
        with deleted_counters_lock:
            services_deleted_count_total += 1
            
        return True, f"Удален сервис '{service_name}' (ID: {service_id})"
        
    except Exception as e:
        return False, f"Ошибка при удалении сервиса '{service_name}' (ID: {service_id}): {e}"

def delete_single_nlist_thread(list_info):
    global lists_deleted_count_total
    list_id = list_info['id']
    list_name = list_info['name']
    try:
        thread_auth_token, thread_server = get_thread_auth()
        
        try:
            thread_server.v2.nlists.delete(thread_auth_token, list_id)
        except Fault as e:
            if e.faultCode == 502:
                thread_server.v2.nlists.list.clear(thread_auth_token, list_id, {})
                thread_server.v2.nlists.delete(thread_auth_token, list_id)
            else:
                raise e
                
        with deleted_counters_lock:
            lists_deleted_count_total += 1
            
        return True, f"Удален список '{list_name}' (ID: {list_id})"
        
    except Exception as e:
        return False, f"Ошибка при удалении списка '{list_name}' (ID: {list_id}): {e}"

def delete_firewall_rules_batch_thread(rule_ids_batch, batch_desc):
    global rules_deleted_count_total
    try:
        thread_auth_token, thread_server = get_thread_auth()
        
        thread_server.v1.firewall.rules.delete(thread_auth_token, rule_ids_batch)
        
        with deleted_counters_lock:
            rules_deleted_count_total += len(rule_ids_batch)
            
        return True, f"Удалена группа правил {batch_desc} (размер: {len(rule_ids_batch)})"
        
    except Exception as e:
        return False, f"Ошибка группы {batch_desc} (размер: {len(rule_ids_batch)}): {e}", rule_ids_batch
print("\n[FIREWALL] --- Удаление правил межсетевого экрана ---")
rules_delete_start_time = time.time()

try:
    print("[FW] Получение списка всех правил межсетевого экрана...")
    all_firewall_rules = get_all_firewall_rules(auth_token)

    rules_to_delete = [
        rule for rule in all_firewall_rules 
        if rule.get('name', '').startswith(FIREWALL_RULE_NAME_PREFIX)
    ]
    print(f"[FW] Найдено правил для удаления: {len(rules_to_delete)}")

    if rules_to_delete:
        rule_ids_to_delete = [rule['id'] for rule in rules_to_delete]
        print(f"[FW] Подготовка к удалению {len(rule_ids_to_delete)} правил (размер пакета: {BATCH_DELETE_SIZE})...")
        
        batches = [rule_ids_to_delete[i:i + BATCH_DELETE_SIZE] for i in range(0, len(rule_ids_to_delete), BATCH_DELETE_SIZE)]
        total_batches = len(batches)
        
        print(f"[FW] Создание {total_batches} пакетов для удаления...")
        
        successfully_deleted_in_batches = 0
        failed_batches_for_fallback = []
        with ThreadPoolExecutor(max_workers=DELETE_THREADS_COUNT) as executor:
            batch_start_time = time.time()
            
            future_to_batch_info = {
                executor.submit(
                    delete_firewall_rules_batch_thread, 
                    batch_ids, 
                    f"#{batch_num + 1}/{total_batches}"
                ): (batch_num + 1, batch_ids) 
                for batch_num, batch_ids in enumerate(batches)
            }
            
            with tqdm(total=total_batches, desc="Формирование пакетов удаления FW", unit="batch", 
                     file=sys.stderr) as pbar_batches:
                
                for future in as_completed(future_to_batch_info):
                    batch_number, batch_ids = future_to_batch_info[future]
                    try:
                        result = future.result()
                        if result[0]:
                            print(f"[FW] {result[1]}")
                            successfully_deleted_in_batches += len(batch_ids)
                        else:
                            print(f"[FW] {result[1]}")
                            failed_batches_for_fallback.extend(result[2])
                    except Exception as e:
                        batch_num, batch_ids = future_to_batch_info[future]
                        print(f"[FW] Необработанная ошибка при удалении группы #{batch_num}: {e}")
                        failed_batches_for_fallback.extend(batch_ids)
                    
                    pbar_batches.update(1)
        
        if failed_batches_for_fallback:
            print(f"[FW] Попытка многопоточного удаления по одному для {len(failed_batches_for_fallback)} правил...")
            rules_for_fallback_delete = [rule for rule in rules_to_delete if rule['id'] in set(failed_batches_for_fallback)]
            
            with ThreadPoolExecutor(max_workers=DELETE_THREADS_COUNT) as executor:
                fallback_start_time = time.time()
                
                future_to_rule = {
                    executor.submit(delete_single_firewall_rule_thread, rule_info): rule_info 
                    for rule_info in rules_for_fallback_delete
                }
                
                with tqdm(total=len(rules_for_fallback_delete), desc="Удаление правил FW", unit="rule", 
                         file=sys.stderr, postfix={"speed": "0 rules/s"}) as pbar_fallback:
                    
                    for future in as_completed(future_to_rule):
                        try:
                            success, message = future.result()
                            print(f"[FW] {message}")
                        except Exception as e:
                            rule_info = future_to_rule[future]
                            print(f"[FW] Необработанная ошибка при fallback-удалении правила '{rule_info.get('name', 'Unknown')}': {e}")
                        
                        elapsed = time.time() - fallback_start_time
                        rules_per_sec = rules_deleted_count_total / elapsed if elapsed > 0 else 0
                        pbar_fallback.set_postfix({"speed": f"{rules_per_sec:.1f} rules/s"})
                        pbar_fallback.update(1)

    else:
        print("[FW] Нет правил для удаления по заданному шаблону.")

except Exception as e:
    print(f"[ERROR] Ошибка при удалении правил межсетевого экрана: {e}")

rules_delete_end_time = time.time()
print(f"[FW] Время на удаление правил: {rules_delete_end_time - rules_delete_start_time:.2f} секунд")
print("\n[SERVICES] --- Удаление сервисов ---")
services_delete_start_time = time.time()

try:
    print("[SVC] Получение списка всех сервисов...")
    all_services = get_all_services(auth_token)

    services_to_delete = [
        service for service in all_services
        if service.get('name', '').startswith(SERVICE_NAME_PREFIX)
    ]
    print(f"[SVC] Найдено сервисов для удаления: {len(services_to_delete)}")

    if services_to_delete:
        print(f"[SVC] Удаление {len(services_to_delete)} сервисов в {DELETE_THREADS_COUNT} потоках...")
        
        with ThreadPoolExecutor(max_workers=DELETE_THREADS_COUNT) as executor:
            svc_start_time = time.time()
            
            future_to_service = {
                executor.submit(delete_single_service_thread, service_info): service_info 
                for service_info in services_to_delete
            }
            
            with tqdm(total=len(services_to_delete), desc="Удаление сервисов", unit="svc", 
                     file=sys.stderr, postfix={"speed": "0 svc/s"}) as pbar_svc:
                
                for future in as_completed(future_to_service):
                    try:
                        success, message = future.result()
                        print(f"[SVC] {message}")
                    except Exception as e:
                        service_info = future_to_service[future]
                        print(f"[SVC] Необработанная ошибка при удалении сервиса '{service_info.get('name', 'Unknown')}': {e}")
                    
                    elapsed = time.time() - svc_start_time
                    svc_per_sec = services_deleted_count_total / elapsed if elapsed > 0 else 0
                    pbar_svc.set_postfix({"speed": f"{svc_per_sec:.1f} svc/s"})
                    pbar_svc.update(1)

    else:
        print("[SVC] Нет сервисов для удаления по заданному шаблону.")

except Exception as e:
    print(f"[ERROR] Ошибка при удалении сервисов: {e}")

services_delete_end_time = time.time()
print(f"[SVC] Время на удаление сервисов: {services_delete_end_time - services_delete_start_time:.2f} секунд")

print("\n[NETWORK LISTS] --- Удаление именованных списков IP ---")
lists_delete_start_time = time.time()

try:
    print("[NL] Получение списка всех именованных списков типа 'network'...")
    all_ip_lists = get_all_nlists(auth_token, 'network')

    lists_to_delete = [
        list_info for list_info in all_ip_lists
        if list_info.get('name', '').startswith(IP_LIST_NAME_PREFIX)
    ]
    print(f"[NL] Найдено списков для удаления: {len(lists_to_delete)}")

    if lists_to_delete:
        print(f"[NL] Удаление {len(lists_to_delete)} списков в {DELETE_THREADS_COUNT} потоках...")
        
        with ThreadPoolExecutor(max_workers=DELETE_THREADS_COUNT) as executor:
            list_start_time = time.time()
            
            future_to_list = {
                executor.submit(delete_single_nlist_thread, list_info): list_info 
                for list_info in lists_to_delete
            }
            
        
            with tqdm(total=len(lists_to_delete), desc="Удаление списков IP", unit="list", 
                     file=sys.stderr, postfix={"speed": "0 list/s"}) as pbar_lists:
                
                for future in as_completed(future_to_list):
                    try:
                        success, message = future.result()
                        print(f"[NL] {message}")
                    except Exception as e:
                        list_info = future_to_list[future]
                        print(f"[NL] Необработанная ошибка при удалении списка '{list_info.get('name', 'Unknown')}': {e}")
                    
                    elapsed = time.time() - list_start_time
                    list_per_sec = lists_deleted_count_total / elapsed if elapsed > 0 else 0
                    pbar_lists.set_postfix({"speed": f"{list_per_sec:.1f} list/s"})
                    pbar_lists.update(1)

    else:
        print("[NL] Нет списков для удаления по заданному шаблону.")

except Exception as e:
    print(f"[ERROR] Ошибка при удалении именованных списков IP: {e}")

lists_delete_end_time = time.time()
print(f"[NL] Время на удаление списков: {lists_delete_end_time - lists_delete_start_time:.2f} секунд")

print("\n--- УДАЛЕНИЕ ЗАВЕРШЕНО ---")
print(f"Удалено правил межсетевого экрана: {rules_deleted_count_total}")
print(f"Удалено сервисов: {services_deleted_count_total}")
print(f"Удалено именованных списков IP: {lists_deleted_count_total}")
total_deleted = rules_deleted_count_total + services_deleted_count_total + lists_deleted_count_total
print(f"Всего удалено объектов: {total_deleted}")
total_time = (rules_delete_end_time - rules_delete_start_time) + \
             (services_delete_end_time - services_delete_start_time) + \
             (lists_delete_end_time - lists_delete_start_time)
print(f"Общее время выполнения скрипта: {total_time:.2f} секунд")

sys.stdout = original_stdout
log_content = log_buffer.getvalue()
log_buffer.close()

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"cleanup.log"

try:
    with open(log_filename, 'w', encoding='utf-8') as log_file:
        log_file.write(log_content)
    print(f"\n[LOG] Полный лог работы записан в '{log_filename}'")
    print("Удаление всех правил окончено!")
except Exception as e:
    print(f"\n[LOG ERROR] Ошибка записи лога в файл '{log_filename}': {e}")