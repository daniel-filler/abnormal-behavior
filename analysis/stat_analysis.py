from .utils import *


def decide(grade, threshold):
    if grade >= threshold:
        return "Suspicious!"
    return "OK"


def analyse(detected, expected, name):
    """
    Gets user statistics and data and check if his authentication is ok
    :param detected: The user authentication
    :param expected: List of classes of the anomalies to check the authentication
    :param name: The user name
    :return: No return value
    """
    if len(detected) == 0 or len(expected) == 0:
        return
    grade = 0.0
    threshold = 0.0
    attr_grades = {}
    for attribute_class in expected:
        attr_grade = attribute_class.evaluate(detected[attribute_class.name])
        attr_grades[attribute_class.name] = attr_grade * attribute_class.weight
        grade += attr_grades[attribute_class.name]
        threshold += attribute_class.threshold
    if decide(grade, threshold) == "Suspicious!":
        sus = open('suspicious.txt', 'a', newline='')
        sus.write(name + ' ' + str(grade) + ' total|\n')
        return
    sus_string = name + ':'
    for attr_class in expected:
        attr_grade = attr_grades[attr_class.name]
        if decide(attr_grade, attr_class.threshold) == 'Suspicious!':
            sus_string += ' ' + attr_class.name + '-' + str(attr_grade) + ', '
    if sus_string != name + ':':
        sus = open('suspicious.txt', 'a', newline='')
        sus.write(sus_string[:len(sus_string) - 2] + '|')


def check(username, detected):
    """
    Collect the anomalies to check if the user authentication is OK
    :param username: The ID of the user
    :param detected: The user authentication
    :return: Call the function analyse
    """
    user_data = on_run_data[username]
    expected = []
    for att in devi_attrs:
        if att == 'Authentication time':
            day = detected["Day"]
            auth_time = AuthenticationTime(user_data["time_std"], user_data["time_avg"],
                                           user_data['days_time'][day]['time_std'],
                                           user_data['days_time'][day]['time_avg'])
            expected += [auth_time]
        elif att == 'ciscoITbuilding':
            auth_loc = Location(user_data['location'].keys())
            expected += [auth_loc]
        elif att == 'Calling-Station-ID':
            auth_mac = MacAddress(user_data['mac_address'])
            expected += [auth_mac]

    analyse(detected, expected, username)
