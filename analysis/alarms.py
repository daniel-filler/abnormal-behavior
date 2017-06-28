import csv
import glob
import os
from analysis.utils import *


def write_all_data(alarm_file):
    """
    Write the data of some/all users to CSV file
    :param alarm_file: hols the users/all users to print
    :return: No return value
    """
    with open(alarm_file) as al_file:
        users = al_file.read().split('\n')
        if users == [""]:
            users_to_print = sorted(on_run_data.keys())
            print_file_name = 'current_users_data.csv'
        else:
            users_to_print = sorted([user for user in users if user in on_run_data.keys()])
            print_file_name = '-'.join(users_to_print) + '.csv'
    with open(print_file_name, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fields_name)
        writer.writeheader()
        for usr in users_to_print:
            usr_data = on_run_data[usr]
            row_write = {fields_name[0]: usr}
            for field in fields_name[1:3]:
                row_write[field] = usr_data[field]
            days_dict = usr_data['days_time']
            for field in fields_name[3:17]:
                c_day = field.split('_')[0]
                c_data = days_dict[c_day]
                s_a = 'time_avg' if field.endswith('avg') else 'time_std'
                row_write[field] = c_data[s_a]
            row_write[fields_name[17]] = usr_data['location']
            writer.writerow(row_write)


def treat_alarms(db):
    """
    Check if there's any alarm to treat and if so, treat it.
    :param db: The database
    :return: No return value
    """
    for alarm_file in glob.glob(alarms_path + '/*'):
        file_name = alarm_file.replace(alarms_path + '\\', '')
        if file_name.startswith('desktop.ini'):
            continue
        if file_name.startswith('user'):
            with open(alarm_file) as al_file:
                users_to_remove = al_file.read().split('\n')
                if users_to_remove == ['all']:
                    answer = input('Are you sure you want to delete the whole DataBase?')
                    if answer == 'Yes'.lower():
                        db.logins.delete_many({})
                        on_run_data.clear()
                else:
                    for usr in users_to_remove:
                        if usr in on_run_data.keys():
                            db.logins.delete_one({'_id': usr})
                            del on_run_data[usr]
        elif file_name.startswith('get'):
            write_all_data(alarm_file)
        os.rename(alarm_file, './' + file_name)
