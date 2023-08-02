from flask import Flask,render_template,redirect,url_for,request
import content as rr
import pandas as pd
from content import aggregation_results,extract_http_payload,extract_email_payload,extract_generic_payload,extract_pdf_payload
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import pyshark


app=Flask(__name__)
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/display')
def display():
    df =rr.extracted_data.to_dict('records')
    return render_template('result.html',result=df)

@app.route('/Summarization')
def Summarization():
    results=rr.aggregation_results(rr.extracted_data)
    return render_template('aggregation.html',results=results)

@app.route('/redirect')
def redirect_to_Summarization():
    return redirect(url_for('Summarization'))



@app.route('/payload_data', methods=['GET', 'POST'])
def payload_data():
    if request.method == 'POST':
        src_ip = request.form.get('src_ip')
        dest_ip = request.form.get('dest_ip')

        filtered_data = rr.extracted_data[
            (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
        ]

        payload_data = []
        for _, row in filtered_data.iterrows():
            payload = get_payload_data(row['Protocol'], row['Info'])
            payload_data.append(payload)

        return render_template('payload_data.html', src_ip=src_ip, dest_ip=dest_ip, payload_data=payload_data)

    return render_template('enter_ip.html')


# Helper function to get payload data based on the protocol
def get_payload_data(protocol, info):
    if protocol == 'HTTP':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_http_payload(pkt)
    elif protocol == 'SMTP':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_email_payload(pkt)
    elif protocol == 'PDF':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_pdf_payload(pkt)
    else:
        pkt = pyshark.packet.Packet(raw=info)
        return extract_generic_payload(pkt)


@app.route('/filter_protocol', methods=['POST'])
def filter_protocol():
    protocol = request.form.get('protocol')
    filtered_data = rr.extracted_data[rr.extracted_data['Protocol'].str.contains(protocol, case=False)]
    df = filtered_data.to_dict('records')
    return render_template('protocol_filter.html', result=df)

@app.route('/filter_protocol_page')
def filter_protocol_page():
    return render_template('protocol_filter.html')


@app.route('/filter_ip', methods=['POST'])
def filter_ip():
    ip_type = request.form.get('ip_type')
    ip_address = request.form.get('ip_address')
    filtered_ips = []

    if ip_type == 'source':
        filtered_ips = rr.extracted_data[rr.extracted_data['Source IP'] == ip_address]['Destination IP'].unique().tolist()
    elif ip_type == 'destination':
        filtered_ips = rr.extracted_data[rr.extracted_data['Destination IP'] == ip_address]['Source IP'].unique().tolist()
    else:
        return "Invalid IP type"

    return render_template('ip_filter.html', ip_type=ip_type, ip_address=ip_address, filtered_ips=filtered_ips)



@app.route('/filter_ip_page')
def filter_ip_page():
    return render_template('ip_filter.html')



@app.route('/ip_details')
def ip_details():
    dest_ip = request.args.get('dest_ip')
    src_ip = request.args.get('src_ip')
    details_data_src_to_dest = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    details_data_dest_to_src = rr.extracted_data[
        (rr.extracted_data['Source IP'] == dest_ip) & (rr.extracted_data['Destination IP'] == src_ip)
    ]

    if not details_data_src_to_dest.empty:
        details = details_data_src_to_dest.to_dict('records')
        return render_template('ip_details.html', src_ip=src_ip, dest_ip=dest_ip, details=details)
    elif not details_data_dest_to_src.empty:
        details = details_data_dest_to_src.to_dict('records')
        return render_template('ip_details.html', src_ip=dest_ip, dest_ip=src_ip, details=details)
    else:
        return "No communication data found for the selected IPs."
    
    
@app.route('/ip_details1')
def ip_details1():
    dest_ip = request.args.get('dest_ip')
    src_ip = request.args.get('src_ip')
    details_data_src_to_dest = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    details_data_dest_to_src = rr.extracted_data[
        (rr.extracted_data['Source IP'] == dest_ip) & (rr.extracted_data['Destination IP'] == src_ip)
    ]

    if not details_data_src_to_dest.empty:
        details = details_data_src_to_dest.to_dict('records')
        return render_template('ip_details1.html', src_ip=src_ip, dest_ip=dest_ip, details=details)
    elif not details_data_dest_to_src.empty:
        details = details_data_dest_to_src.to_dict('records')
        return render_template('ip_details1.html', src_ip=dest_ip, dest_ip=src_ip, details=details)
    else:
        return "No communication data found for the selected IPs."
    


@app.route('/filter_ips', methods=['POST'])
def filter_ips():
    src_ip = request.form.get('src_ip')
    dest_ip = request.form.get('dest_ip')
    
    filtered_data = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    
    protocol_counts = filtered_data['Protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    
    info_counts = filtered_data['Info'].value_counts().reset_index()
    info_counts.columns = ['Info', 'Count']
    custom_col=['#8a4fff']
    
    protocol_chart = BytesIO()
    plt.figure(figsize=(8, 5))
    plt.pie(protocol_counts['Count'], labels=protocol_counts['Protocol'], autopct='%1.1f%%',colors=custom_col)
    plt.title('Protocol Distribution')
    plt.savefig(protocol_chart, format='png')
    protocol_chart.seek(0)
    protocol_chart_url = base64.b64encode(protocol_chart.getvalue()).decode()

    info_chart = BytesIO()
    plt.figure(figsize=(8, 5))
    plt.pie(info_counts['Count'], labels=info_counts['Info'], autopct='%1.1f%%')
    plt.title('Data Type Distribution')
    plt.savefig(info_chart, format='png')
    info_chart.seek(0)
    info_chart_url = base64.b64encode(info_chart.getvalue()).decode()
    
    return render_template('IP_filter_both.html', src_ip=src_ip, dest_ip=dest_ip, data=filtered_data.to_dict('records'), protocol_chart_url=protocol_chart_url, info_chart_url=info_chart_url)
@app.route('/filter_both_ip')
def filter_both_ip():
    return render_template('IP_filter_both.html')





if __name__ == '__main__':
    app.run(debug=True)