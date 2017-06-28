1. In the file utile.py, Change the system parmeter and paths as needed for your own use
	- To add a new anomly, do as follow:
		- in the file utils.py: 
			- Create a new class of the requested anomly which include weight, theshold, name, c'tor and method evaluate.
				- weight - The attribute weight which would calculate to the total grade.
				- threshold - The maximum grade which the anomaly allowed to reach, beyond this - ab alarm would be raise.
				- name - The anomaly name as it in the syslog file.
				- c'tor - The class constructor which initiate with the requested authentication.
				- evaluate - Funtion which get only 1 parameter - a detected value of this anomaly and check if the detected parmeter stand with the initiated parameters in the c'tor 
			- Add the anomaly name (as it presented in the syslog) to the "attr_array" and devi_attr".
		- In the file stat_analysis.py:
			- In the fuction "check" add a registration of the new class and add it to the arrat "expected".
		- In the file get_data.py:
			- In the function "get_statistics", add the new attributeto the "data_dict" as you want its statistics to be checked.
 
2. To connect to the MongoDB, Run the command from the utils.py

3. To run the program, run the command: python abnormal_DB.py in the command line