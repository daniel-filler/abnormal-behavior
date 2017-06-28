import os
import glob
import pymongo
import time
import datetime as dt
from analysis.utils import *
from analysis.alarms import treat_alarms
from analysis.stat_analysis import check
from analysis.get_data import get_users_data, get_statistics


# client = pymongo.MongoClient(db_path)
client = pymongo.MongoClient()
db = client.test


def read_syslogs(syslogs_path, path_for_checked):
    """
    Reading the syslogs and gets data for each user
    :param syslogs_path: The path which contains the syslogs
    :param path_for_checked: The path which each checked syslog wil go to after use its data
    :return: dictionary for each user where the key is user ID and ahe value is the authentications of the user
    """
    users_data = {}
    for syslog_file in glob.glob(syslogs_path + '/*'):
        if not syslog_file.replace(syslogs_path + "\\", "").startswith(syslogs_filename_start_witch):
            continue
        with open(syslog_file) as sys_log_file:
            sys_readed = sys_log_file.read().split("\n")
            succeeded = [s for s in sys_readed if successful_authentication_mark in s]
            user_succ = [us for us in succeeded if machine_person in us]
            machine_succ = [us for us in succeeded if machine_person not in us]
            for authentication in user_succ:
                u_id, u_data = get_users_data(authentication.split(", "))
                if u_id in users_data.keys():
                    users_data[u_id] += [u_data]
                else:
                    users_data[u_id] = [u_data]
            for authentication in machine_succ:
                u_id, u_data = get_users_data(authentication.split(", "))
                if u_id in users_data.keys():
                    users_data[u_id] += [u_data]
                else:
                    users_data[u_id] = [u_data]
        sys_log_file.close()
        os.rename(syslog_file, path_for_checked + syslog_file.replace(syslogs_path + "\\", ""))
    return users_data


def write_to_db(users_data):
    """
    Gets the users data and add it to the Database and analyze each user's data
    :param users_data: A dictionary where its key is user ID and the value is the last authentications of the user
    :return: No return value
    """
    user_data_dict = {}
    for usr_id in users_data.keys():
        user_data = users_data[usr_id]
        u_d_len = len(user_data)
        if u_d_len > day_to_remember:
            user_data = user_data[u_d_len - day_to_remember:]
        user_data_dict[usr_id] = user_data
        on_run_data[usr_id] = get_statistics(user_data_dict[usr_id])
    list_for_db = [{"_id": user_id, "attributes": user_data_dict[user_id]} for user_id in user_data_dict.keys()]
    db.logins.insert(list_for_db)


def add_to_db():
    """
    Treat the user syslogs
    :return: No return value
    """
    path = os.listdir(db_syslogs_path)
    if len(path) == 0 or len(path) == 1 and 'desktop.ini' in path:
        return
    # """
    # Clear the database
    # """
    db.logins.delete_many({})
    start_monitor = time.time()
    users_auths = read_syslogs(db_syslogs_path, checked_syslogs_path + '\\')
    print(time.time() - start_monitor)
    write_to_db(users_auths)
    print(time.time() - start_monitor)


# """
#     function for test
# """
# for presentation, return Syslogs to input file
# def return_to_test():
#     if os.path.exists('suspicious.txt'):
#         os.remove('suspicious.txt')
#     i = 0
#     for syslog_file in glob.glob("./checked_Syslogs/*"):
#         if not syslog_file.replace("./checked_Syslogs\\", "").startswith('Sys'):
#             continue
#         if i < 50:
#             os.rename(syslog_file, db_syslogs_path + '\\' + syslog_file.replace("./checked_Syslogs\\", ""))
#         else:
#             os.rename(syslog_file, monitoring_test_path + '\\' + syslog_file.replace("./checked_Syslogs\\", ""))
#         i += 1
#     for syslog_file in glob.glob("./checked_Syslogs_test/*"):
#         if not syslog_file.replace("./checked_Syslogs_test\\", "").startswith('Sys'):
#             continue
#         os.rename(syslog_file, monitoring_test_path + '/' + syslog_file.replace("./checked_Syslogs_test\\", ""))
#
#
# # """
# #     function for test
# # """
# def add_to_test_dir():
#     for syslog_file in glob.glob(monitoring_test_path + "/*"):
#         if not syslog_file.replace(monitoring_test_path + "\\", "").startswith('Sys'):
#             continue
#         os.rename(syslog_file, './Syslogs_Test\\' + syslog_file.replace(monitoring_test_path + '\\', ''))
#         break
    # for syslog_file in glob.glob("./*"):
    #     if os.path.isdir(syslog_file) or not syslog_file.replace(".\\", "").startswith('Sys'):
    #         continue
    #     os.rename(syslog_file, './Syslogs_Test\\' + syslog_file)
    # for syslog_file in glob.glob("./checked_Syslogs_test/*"):
    #     if not syslog_file.replace("./checked_Syslogs_test\\", "").startswith('Sys'):
    #         continue
    #     os.rename(syslog_file, './Syslogs_Test\\' + syslog_file)


def night_update(users_to_update):
    """
    Update the Database once a day at night time
    :param users_to_update: The users which logged in today
    :return: No return value
    """
    for user in users_to_update.keys():
        user_id = user
        new_data = users_to_update[user_id]
        cursor = db.logins.find({"_id": user_id})
        if cursor.count() == 0:
            db.logins.insert_one({"_id": user_id, "attributes": new_data})
        else:
            new_data_len = len(new_data)
            if new_data_len >= day_to_remember:
                statistics_array = new_data[new_data_len - day_to_remember:]
                new_data = statistics_array
            else:
                db_data = [x for x in [d for d in cursor]]
                statistics_array = [x["attributes"] for x in db_data][0] + new_data
                while len(statistics_array) > day_to_remember:
                    statistics_array = statistics_array[1:]
                    db.logins.update({"_id": user_id}, {'$pop': {"attributes": -1}})
            on_run_data[user] = get_statistics(statistics_array)
            for data in new_data:
                db.logins.update({"_id": user_id}, {'$push': {"attributes": data}}, upsert=True)

    for syslog_file in glob.glob(runtime_checked_syslogs_path + "/*"):
        if not syslog_file.replace(runtime_checked_syslogs_path + "\\", "").startswith(syslogs_filename_start_witch):
            continue
        os.rename(syslog_file, syslog_file.replace(runtime_checked_syslogs_path + '\\', checked_syslogs_path + '\\'))


def update_after_wake_up():
    """
    Update the statistics in case the system was shut down
    :return: No return value
    """
    cursors = db.logins.find()
    for c in cursors:
        user_id = c['_id']
        array = c["attributes"]
        on_run_data[user_id] = get_statistics(array)


# def is_add_to_test():
#     curr_time = int(time.time())
#     curr_time_mod = curr_time % 13
#     if curr_time_mod > 4:
#         add_to_test_dir()


def monitor_real_time():
    """
    Run forever and monitor if there's new syslogs or any alarms to treat
    :return: No return value
    """
    users_update = {}
    is_updated = True
    if len(list(on_run_data.keys())) == 0:
        update_after_wake_up()
    while True:
        start_monitor = time.time()
        # is_add_to_test()
        current_checked_users = read_syslogs(runtime_syslogs_path, runtime_checked_syslogs_path + "\\")
        for usr in current_checked_users.keys():
            if usr in users_update.keys():
                continue
            users_update[usr] = []
        for usr in current_checked_users.keys():
            curr_data = current_checked_users[usr]
            if usr in on_run_data.keys():
                users_update[usr] += curr_data
                for data in curr_data:
                    check(usr, data)
            else:
                users_update[usr] += curr_data
        treat_alarms(db)

        if current_checked_users != {}:
            night_update(users_update)
            users_update.clear()
        curr_time = dt.datetime.now().time()
        print(curr_time)
        current_time = time.time()
        if current_time - start_monitor < monitoring_scale:
            time.sleep(monitoring_scale - (current_time - start_monitor))
        # continue
        if is_updated and no_update_time < curr_time < time_to_over_night:
            is_updated = False
        if not is_updated and curr_time > time_to_over_night:
            night_update(users_update)
            users_update.clear()
            is_updated = True


if __name__ == "__main__":

    # return_to_test()
    add_to_db()
    monitor_real_time()
