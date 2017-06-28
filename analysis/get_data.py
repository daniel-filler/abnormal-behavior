import numpy as np
import calendar
from analysis.utils import *


def average_time(times):
    """
    Gets a list of authentications time and return the average and the standard deviation
    :param times: List of authentications time
    :return: Average and STD of the authentications time
    """
    if len(times) < min_occurrences:
        return '', ''
    total_seconds = [d_t.hour * hour_sec + d_t.minute * minute_sec + d_t.second for d_t in
                     [datetime.strptime(tt, "%H:%M:%S") for tt in times]]
    auth_num = len(times)
    avg_sec = sum(total_seconds) / auth_num
    minutes, seconds = divmod(int(avg_sec), 60)
    hours, minutes = divmod(minutes, 60)
    sec_std = np.std(np.array(total_seconds))
    minutes_std, seconds_std = divmod(int(sec_std), 60)
    hours_std, minutes_std = divmod(minutes_std, 60)
    avg = str(hours) + ":" + str(minutes) + ":" + str(seconds)
    std = str(hours_std) + ":" + str(minutes_std) + ":" + str(seconds_std)
    return avg, std


def get_time(authentication_time):
    splited_auth = authentication_time.split(".")[0]
    date_hour = datetime.strptime(splited_auth, "%Y-%m-%d %H:%M:%S")
    return {"Day":  calendar.day_name[date_hour.date().weekday()], "Authentication date": str(date_hour.date()),
            "Authentication time": str(date_hour.time())}


def get_users_data(user_data):
    """
    Gets a user authentication and return it's relevant data as a dictionary
    :param user_data: List of the user authentication
    :return: User ID ant a dictionary of his authentication
    """
    user_data_short = [x for x in user_data if not x.startswith('Step') and not x.startswith('memberOf')]
    relevant_data = get_time(user_data_short[0])
    user_id = [u_id.split("=")[1].replace("/", "") for u_id in user_data_short if u_id.startswith("UserName")][0]

    for a in attr_array:
        if a == "Day" or a == "UserName" or a == "Authentication date" or a == "Authentication time":
            continue
        d = {a: data.split("=")[1] for data in user_data_short if data.startswith(a)}
        if d != {}:
            relevant_data[a] = d[a]
        else:
            relevant_data[a] = ''
    return user_id, relevant_data


def get_statistics(user_data):
    """
    analyze the user authentications by the relevant parameters
    :param user_data: User authentication to analyze
    :return: A dictionary of the statistics of the user
    """
    data_dict = {}

    # total time analyse
    times = [daily['Authentication time'] for daily in user_data]
    time_avg, time_std = average_time(times)
    data_dict["time_std"] = time_std
    data_dict["time_avg"] = time_avg

    # each day analyse
    days_times = {d: [] for d in days}
    for data in user_data:
        d_time = data['Authentication time']
        day = data['Day']
        days_times[day] += [d_time]
    days_data = {d: {} for d in days}
    for d in days:
        t_a, t_s = average_time(days_times[d])
        days_data[d] = {'time_avg': t_a, 'time_std': t_s}
    data_dict["days_time"] = days_data

    auth_locations = {}
    for daily in user_data:
        location = daily['ciscoITbuilding']
        if location in auth_locations.keys():
            auth_locations[location] += 1
        else:
            auth_locations[location] = 1
    data_dict['location'] = auth_locations

    auth_mac_addresses = list(set([daily['Calling-Station-ID'] for daily in user_data]))
    data_dict['mac_address'] = auth_mac_addresses

    return data_dict
