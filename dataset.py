import pandas as pd
import os
import sys
import time
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.pyplot import MultipleLocator
from multiprocessing import Pool


# extract info
def sperate(line, is_testbed):
    line = line.strip()
    if is_testbed == True:
        start_ts_unix = None
        fields1 = line.split(";")
        fields2 = fields1[2].split()
        fields = fields1[:2] + fields2

        ts_unix = float(fields[0])
        if start_ts_unix is None:
            start_ts_unix = ts_unix
        ts_unix -= start_ts_unix
        time = int(float(ts_unix) * 1000)
        node = int(fields[1][3:])
    else:
        fields = line.split()
        node = int(fields[1])
        time = int(fields[0]) // 1000

    return node, time


def msg_type(line):
    ty = np.zeros((8, 1))
    if "EB" in line:
        ty[0] = 1
    if ("sending" in line or "received " in line) and "DIO" in line:
        ty[1] = 1
    if ("sending" in line or "received " in line) and "DIS" in line:
        ty[2] = 1
    if "sending" in line and "DAO" in line and "to" in line:
        ty[3] = 1
    if "sending" in line and "DAO-ACK" in line:
        ty[4] = 1
    if ("send" in line and "packet" in line) or ("sent" in line and "packet" in line):
        ty[5] = 1
    if "sending" in line and "multicast" in line:
        ty[6] = 1
    if "sending" in line and "unicast" in line:
        ty[7] = 1

    return ty

def msg_type_count(line,ty_count):

    if "EB" in line:
        ty_count[0] += 1
    if ("sending" in line or "received " in line) and "DIO" in line:
        ty_count[1] += 1
    if ("sending" in line or "received " in line) and "DIS" in line:
        ty_count[2] += 1
    if "sending" in line and "DAO" in line and "to" in line:
        ty_count[3] += 1
    if "sending" in line and "DAO-ACK" in line:
        ty_count[4] += 1
    if ("send" in line and "packet" in line) or ("sent" in line and "packet" in line):
        ty_count[5] += 1
    if "sending" in line and "multicast" in line:
        ty_count[6] += 1
    if "sending" in line and "unicast" in line:
        ty_count[7] += 1

    return ty_count


def find_rank(line):
    rank = '-'
    if ("initialized" in line or "sending" in line) and "rank" in line:
        rank_index = line.find("rank")
        if rank_index != -1:

            digit_start = rank_index + len("rank")

            while digit_start < len(line) and line[digit_start].isspace():
                digit_start += 1

            digit_end = digit_start
            while digit_end < len(line) and line[digit_end].isdigit():
                digit_end += 1

            rank = int(line[digit_start:digit_end])


    return rank


def find_source(line):
    src = '-'
    if "received" in line and "from" in line and 'EB' not in line:
        words = line.split()
        index_of_from = words.index("from")
        word_after_from = words[index_of_from + 1]
        word_after_from = word_after_from.replace(',', '')
        if ":" in word_after_from:
            src = int(word_after_from.split(":")[-1], 16)
        else:
            src = int(word_after_from.split(".")[-1], 16)
    return src


def find_dest(line):
    dst = '-'
    if ("sending" in line or "sent" in line or "send" in line) and "DIS" not in line and "to" in line:
        words = line.split()
        index_of_to = words.index("to")
        word_after_to = words[index_of_to + 1]
        word_after_to = word_after_to.replace(',', '')
        if ":" in word_after_to:
            dst = int(word_after_to.split(":")[-1], 16)
        else:
            dst = int(word_after_to.split(".")[-1], 16)
    return dst


def find_version(line):
    version = '-'
    if "version" in line and "received" in line:
        words = line.split()
        index_of_to = words.index("version")
        word_after_to = words[index_of_to + 1]
        version = word_after_to.replace(',', '')
    return version

def count_send(line,sent_count):
    if "sent" in line:
        sent_count +=1

    return sent_count


def count_receives(line,receive_count):
    if "received" in line:
        receive_count +=1

    return receive_count




# 文件路径
file_path = r'logfile\SHA-4.testlog'


def process_file_chunks(chunk):
    df_chunk = pd.DataFrame(columns=[ 'Time','NodeNumber', 'Send', 'Receive', 'EB_count',
                                     'DAO_count', 'DAO_ACK_count', 'packet_count', 'DIO_interval',
                                      'DIS_interval','DIO_count', 'DIS_count','version_count' ,
                                      'Multicast_count','Unicast_count','Node_type', 'Attack_type'])
    malicious = [5,15,25,35,45]
    #0-NA,1-DFA,2-VNA,3-SFA,4-SHA
    attack_type = 4
    nodes=[]
    t_start=0
    dio_interval = {}
    dis_interval = {}
    dis_count = {}
    dio_count = {}
    last_dis_time = {}
    last_dio_time = {}

    msg_ty_count={}
    ty = np.zeros((8, 1))
    send_count={}
    receive_count={}
    #new_rows = []
    version_count = {}
    versions = {}


    for line in chunk:
        msg_ty = msg_type(line)
        if np.sum(msg_ty) != 0:
            node, time = sperate(line, False)
            if time - t_start >= 180000:# window size


                for no in nodes:
                    count = msg_ty_count[no]
                    if dio_interval[no]:
                        dio_avg = np.mean(dio_interval[no])
                    else:
                        dio_avg = 999999
                    if dis_interval[no]:
                        dis_avg = np.mean(dis_interval[no])
                    else:
                        dis_avg = 999999
                    #dio_avg = np.mean(dio_interval[no])
                    #dis_avg = np.mean(dis_interval[no])
                    if no in malicious:
                        att = 1
                        att_ty = attack_type
                    else :
                        att = 0
                        att_ty= 0


                    new_row = {
                        'Time': f"{t_start}~{time}",
                        'NodeNumber': no,
                        'Send': send_count[no],
                        'Receive': receive_count[no],
                        'EB_count': int(count[0, 0]),
                        'DAO_count': int(count[3, 0]),
                        'DAO_ACK_count': int(count[4, 0]),
                        'packet_count': int(count[5, 0]),
                        'DIO_interval': dio_avg,
                        'DIS_interval': dis_avg,
                        'DIO_count': dio_count[no],
                        'DIS_count': dis_count[no],
                        'version_count' : int(version_count[no]),
                        'Multicast_count': int(count[6, 0]),
                        'Unicast_count': int(count[7, 0]),
                        'Node_type': att,
                        'Attack_type': att_ty
                    }

                    #new_rows.append(new_row)
                    df_chunk = pd.concat([df_chunk, pd.DataFrame([new_row])], ignore_index=True)



                nodes=[]
                dio_interval = {}
                dis_interval = {}
                dis_count = {}
                dio_count = {}
                msg_ty_count = {}
                send_count = {}
                receive_count = {}
                t_start = time
                version_count={}

            if node not in nodes:
                nodes.append(node)

            if node not in msg_ty_count:
                msg_ty_count[node] = ty
            if node not in dio_count:
                dio_count[node] = 0
            if node not in dis_count:
                dis_count[node] = 0
            if node not in send_count:
                send_count[node] = 0
            if node not in receive_count:
                receive_count[node] = 0
            if node not in dio_interval:
                dio_interval[node] = []
            if node not in last_dio_time:
                last_dio_time[node] = 0
            if node not in dis_interval:
                dis_interval[node] = []
            if node not in last_dis_time:
                last_dis_time[node] = 0
            if node not in version_count:
                version_count[node] = 0


            msg_ty_count[node] = msg_type_count(line,msg_ty_count[node])
            receive_count[node] = count_receives(line, receive_count[node])
            send_count[node] = count_receives(line, send_count[node])

            if "sending" in line and "DIO" in line:
                interval = time - last_dio_time[node]

                dio_interval[node].append(interval)

                last_dio_time[node] = time

                dio_count[node] = dio_count[node] + 1

            if "sending" in line and "DIS" in line:
                interval = time - last_dis_time[node]

                dis_interval[node].append(interval)

                last_dis_time[node] = time

                dis_count[node] = dis_count[node] + 1

            src=find_source(line)
            version = find_version(line)
            if version != '-':
                if src != '-':
                    if src not in version_count:
                        version_count[src] = 0
                    if src not in versions:
                        versions[src] = '-'
                    if version != versions[src]:
                        version_count[src] += 1
                        versions[src]=version



    return df_chunk


if __name__ == '__main__':
    with open(file_path, "r") as f:
        lines = f.readlines()

    max_processes = 6

    chunk_size = len(lines) // max_processes
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

    with Pool(processes=max_processes) as pool:
        result_chunks = pool.map(process_file_chunks, chunks)
    df_combined = pd.concat(result_chunks, ignore_index=True)

    try:
        df_existing = pd.read_excel('data.xlsx')
    except FileNotFoundError:
        df_existing = pd.DataFrame()

    df_combined = pd.concat([df_existing, df_combined], ignore_index=True)


    output_excel_path = 'data.xlsx'
    df_combined.to_excel(output_excel_path, index=False)
