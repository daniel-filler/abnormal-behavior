from datetime import datetime

# First command to run in command line
# "C:\Program Files\MongoDB\Server\3.4\bin\mongod" --dbpath C:\MongoServer

db_path = "mongodb://dbadmin:xhxnvrtah,@cluster0-shard-00-00-4mufe.mongodb.net:27017,cluster0-shard-00-01-4mufe.mongodb.net:27017,cluster0-shard-00-02-4mufe.mongodb.net:27017/Cluster0?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin"
# The path which contain the initiate syslogs
db_syslogs_path = "./DB_Syslogs1"
# The path where new syslogs go to
runtime_syslogs_path = "./Syslogs_Test"
# For test
# monitoring_test_path = './Monitoring1'
# The suffix of syslog files
syslogs_filename_start_witch = 'Sys'
# The sign to get a successful authentication
successful_authentication_mark = "5200 NOTICE"
# The sign to devide between user authentication and machine authentication
machine_person = "employeeType"
# The path where a checked syslog file go to
checked_syslogs_path = './checked_Syslogs'
# The path where a checked syslog files go to before night update
runtime_checked_syslogs_path = "./checked_Syslogs_test"
# The path of alarms
alarms_path = "./analysis/alarm_analysis"

fields_name = ['UserName', "time_std", "time_avg", 'Sunday_std', 'Sunday_avg', 'Monday_std',
               'Monday_avg', 'Tuesday_std', 'Tuesday_avg', 'Wednesday_std', 'Wednesday_avg',
               'Thursday_std', 'Thursday_avg', 'Friday_std', 'Friday_avg',
               'Saturday_std', 'Saturday_avg', 'Locations']

# attribute name: weight
attr_array = ["Day", "Authentication date", "Authentication time", "Calling-Station-ID",
              "Device IP Address", "DestinationIPAddress", "UserName", "Protocol",
              "NetworkDeviceName", "NAS-Port", "Framed-IP-Address", "Called-Station-ID",
              "NAS-Port-Id", "NetworkDeviceProfileName", "NetworkDeviceProfileId",
              "IsThirdPartyDeviceFlow", "RadiusFlowType", "SSID", "AuthenticationMethod",
              "SelectedAuthorizationProfiles", "IdentityGroup", "SelectedAuthenticationIdentityStores",
              "AuthenticationStatus", "NetworkDeviceGroups", "IdentityPolicyMatchedRule",
              "AuthorizationPolicyMatchedRule", "ciscoITbuilding"]

# attributes to be checked by average and standard deviation
devi_attrs = ["Authentication time", "ciscoITbuilding", "Calling-Station-ID"]

day_to_remember = 30

hour_sec = 3600
minute_sec = 60
day_sec = 86400.0
half_day_sec = day_sec / 2

monitoring_scale = 10  # Seconds

time_to_over_night = datetime.strptime('20:02:00', "%H:%M:%S").time()

no_update_time = datetime.strptime('08:00:00', "%H:%M:%S").time()

# minimum occurrence of attribute for calculate its anomaly
min_occurrences = 3

days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

on_run_data = {}


class AuthenticationTime:

    weight = 10
    threshold = 100
    name = 'Authentication time'

    def __init__(self, time_std, time_avg, day_time_std, day_time_avg):
        self.time_std = time_std
        self.time_avg = time_avg
        self.day_time_std = day_time_std
        self.day_time_avg = day_time_avg

    @staticmethod
    def convert_time_to_seconds(ttime):
        time_to_convert = datetime.strptime(ttime, "%H:%M:%S").time()
        time_seconds = time_to_convert.hour * hour_sec + time_to_convert.minute * minute_sec + time_to_convert.second
        return time_seconds

    def evaluate(self, new_time):
        new_val_time = self.convert_time_to_seconds(new_time)
        ret_val = 0.0
        if '' in [self.time_std, self.time_avg]:
            return ret_val
        std_val_sec = self.convert_time_to_seconds(self.time_std)
        avg_val_sec = self.convert_time_to_seconds(self.time_avg)
        if '' not in [self.day_time_std, self.day_time_avg]:
            day_std_val_sec = self.convert_time_to_seconds(self.day_time_std)
            day_avg_val_sec = self.convert_time_to_seconds(self.day_time_avg)
            if day_avg_val_sec - day_std_val_sec <= new_val_time <= day_avg_val_sec + day_std_val_sec:
                return ret_val
            elif day_sec + (day_avg_val_sec - day_std_val_sec) <= new_val_time\
                    <= day_sec + day_avg_val_sec + day_std_val_sec:
                return ret_val
            else:
                day_gap = day_avg_val_sec - new_val_time
                if day_gap < 0 and abs(day_gap) > half_day_sec:
                    day_gap = day_sec - abs(day_gap)
                ret_val += (day_gap ** 2) / half_day_sec

        if avg_val_sec - std_val_sec <= new_val_time <= avg_val_sec + std_val_sec:
            return ret_val
        elif day_sec + (avg_val_sec - std_val_sec) <= new_val_time \
                <= day_sec + avg_val_sec + std_val_sec:
            return ret_val
        gap = avg_val_sec - new_val_time
        if gap < 0 and abs(gap) > half_day_sec:
            gap = day_sec - abs(gap)
        ret_val += (gap ** 2) / half_day_sec
        return ret_val / 2


class Location:

    weight = 51
    threshold = 50
    name = 'ciscoITbuilding'

    def __init__(self, location):
        self.current_location = location

    def evaluate(self, new_location):
        if new_location not in self.current_location:
            return 1
        return 0


class MacAddress:

    weight = 51
    threshold = 50
    name = 'Calling-Station-ID'

    def __init__(self, mac_address):
        self.current_mac_address = mac_address

    def evaluate(self, new_mac_address):
        if new_mac_address not in self.current_mac_address:
            return 1
        return 0
