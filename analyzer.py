from flask import Flask, request, render_template, redirect
import os
import pandas as pd
import re



# Define the upload folder where log files will be stored temporarily
UPLOAD_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'log'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to parse a single line of the log file
def parse_log_line(line):
    fields = re.split(r' +', line.strip())
    if len(fields) < 11:
        return None  # Skip lines that don't have enough fields

    # Extract fields from the line
    log_data = {
        'Date': fields[0],
        'Time': fields[1],
        'Action': fields[2],
        'Protocol': fields[3],
        'Src_IP': fields[4],
        'Dst_IP': fields[5],
        'Src_Port': fields[6] if fields[6] != '-' else None,
        'Dst_Port': fields[7] if fields[7] != '-' else None,
        'Size': fields[8] if fields[8] != '-' else None,
        'TCP_Flags': fields[9] if fields[9] != '-' else None,
        'Info': " ".join(fields[10:])  # The rest of the line is 'Info'
    }
    return log_data

# Function to analyze the uploaded log file
def analyze_uploaded_log(file):
    log_data_list = []
    
    with open(file, 'r') as file:
        next(file)  # Skip the header line
        for line in file:
            if line.strip():  # Skip empty lines
                parsed_line = parse_log_line(line)
                if parsed_line:
                    log_data_list.append(parsed_line)
    
    # Convert list of dicts to DataFrame
    log_df = pd.DataFrame(log_data_list).dropna(how='all')
    
    if not log_df.empty:
        log_df['DateTime'] = pd.to_datetime(log_df['Date'] + ' ' + log_df['Time'], errors='coerce')
        log_df = log_df.drop(['Date', 'Time'], axis=1)
        log_df['Size'] = pd.to_numeric(log_df['Size'], errors='coerce')

        # Basic analysis
        action_counts = log_df['Action'].value_counts()
        top_blocked_ports = log_df[log_df['Action'] == 'BLOCK']['Dst_Port'].value_counts().head(10)
        suspicious_ips = log_df[log_df['Action'] == 'BLOCK']['Src_IP'].value_counts().head(10)
        
        # Function to identify potential DDoS threats
        def identify_ddos_attempts(log_df):
            src_ip_counts = log_df.groupby(['Src_IP', pd.Grouper(key='DateTime', freq='Min')]).size()
            potential_ddos = src_ip_counts[src_ip_counts > 100]  # Threshold is set to 100 requests per minute
            return potential_ddos

        # Function to identify potential brute force attacks
        def identify_brute_force_attempts(log_df):
            failed_logins = log_df[log_df['Info'].str.contains('Failed login', case=False)]
            brute_force_attempts = failed_logins.groupby('Src_IP').size().sort_values(ascending=False)
            potential_brute_force = brute_force_attempts[brute_force_attempts > 5]  # Threshold is set to more than 5 failed attempts
            return potential_brute_force

        # Function to identify potential port scanning
        def identify_port_scanning(log_df):
            port_scan_attempts = log_df[log_df['Action'] == 'BLOCK'].groupby('Src_IP')['Dst_Port'].nunique()
            potential_port_scans = port_scan_attempts[port_scan_attempts > 1]  # Arbitrary threshold of unique ports
            return potential_port_scans

        # Function to identify potential horizontal scanning
        def identify_horizontal_scanning(log_df):
            horizontal_scan_attempts = log_df[log_df['Action'] == 'BLOCK'].groupby(['Src_IP', 'Dst_Port']).size()
            potential_horizontal_scans = horizontal_scan_attempts[horizontal_scan_attempts > 10]  # Arbitrary threshold
            return potential_horizontal_scans

        # Function to identify suspicious traffic on uncommon ports
        def identify_suspicious_uncommon_port_traffic(log_df):
            common_ports = {'80', '443', '22', '21'}  # Define a set of common ports
            uncommon_port_traffic = log_df[~log_df['Dst_Port'].isin(common_ports) & (log_df['Action'] == 'ALLOW')]
            suspicious_uncommon_port_traffic = uncommon_port_traffic.groupby(['Src_IP', 'Dst_Port']).size()
            return suspicious_uncommon_port_traffic[suspicious_uncommon_port_traffic > 2]  # Arbitrary threshold

        # Function to identify repeated actions from the same IP
        def identify_repeated_actions(log_df):
            repeated_actions = log_df.groupby(['Src_IP', 'Info']).size()
            potential_repeated_actions = repeated_actions[repeated_actions > 10]  # Arbitrary threshold
            return potential_repeated_actions

        # Function to identify unauthorized SSH access attempts
        def identify_unauthorized_ssh_access(log_df):
            ssh_attempts = log_df[(log_df['Info'].str.contains('SSH', case=False)) & 
                                (log_df['Action'] == 'BLOCK')]
            return ssh_attempts['Src_IP'].value_counts()

        # Function to identify SQL Server access attempts
        def identify_sql_server_access_attempts(log_df):
            sql_attempts = log_df[(log_df['Info'].str.contains('SQL', case=False)) & 
                                (log_df['Action'] == 'BLOCK')]
            return sql_attempts['Src_IP'].value_counts()

        # Identify potential threats
        ddos_attempts = identify_ddos_attempts(log_df)
        brute_force_attempts = identify_brute_force_attempts(log_df)
        port_scanning_attempts = identify_port_scanning(log_df)
        horizontal_scanning_attempts = identify_horizontal_scanning(log_df)
        uncommon_port_traffic = identify_suspicious_uncommon_port_traffic(log_df)
        unauthorized_ssh_attempts = identify_unauthorized_ssh_access(log_df)
        sql_server_access_attempts = identify_sql_server_access_attempts(log_df)
        repeated_actions = identify_repeated_actions(log_df)
        
        return log_df, action_counts, top_blocked_ports, suspicious_ips, ddos_attempts, brute_force_attempts, port_scanning_attempts, horizontal_scanning_attempts, uncommon_port_traffic, unauthorized_ssh_attempts, sql_server_access_attempts, repeated_actions
    else:
        return None, None, None, None, None, None, None, None, None, None, None, None

# Function to check if the file has a valid extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Define the route for uploading a log file
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # Save the uploaded file to the UPLOAD_FOLDER
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'uploaded.log'))
            # Analyze the uploaded log file
            log_data, actions, blocked_ports, ips, ddos_attempts, brute_force_attempts, port_scanning_attempts, horizontal_scanning_attempts, uncommon_port_traffic, unauthorized_ssh_attempts, sql_server_access_attempts, repeated_actions = analyze_uploaded_log(os.path.join(app.config['UPLOAD_FOLDER'], 'uploaded.log'))
            return render_template('results.html', log_data=log_data, actions=actions, blocked_ports=blocked_ports, ips=ips, ddos_attempts=ddos_attempts, brute_force_attempts=brute_force_attempts, port_scanning_attempts=port_scanning_attempts, horizontal_scanning_attempts=horizontal_scanning_attempts, uncommon_port_traffic=uncommon_port_traffic, unauthorized_ssh_attempts=unauthorized_ssh_attempts, sql_server_access_attempts=sql_server_access_attempts, repeated_actions=repeated_actions)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
