import pandas as pd
import os
import sys
import time
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.pyplot import MultipleLocator
from multiprocessing import Pool


# extract info
def sperate(line, is_testbed,start_ts_unix):
    line = line.strip()
    if is_testbed == True:
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

    return node, time,start_ts_unix


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


def find_rank(line):
    rank = '-'
    if ("initialized" in line or "sending" in line) and "rank" in line:
        rank_index = line.find("rank")
        # 如果找到了 rank，继续提取数字
        if rank_index != -1:
            # 从 rank 后面的位置开始查找数字
            digit_start = rank_index + len("rank")

            # 找到第一个非空格字符的位置
            while digit_start < len(line) and line[digit_start].isspace():
                digit_start += 1

            # 找到数字的结束位置
            digit_end = digit_start
            while digit_end < len(line) and line[digit_end].isdigit():
                digit_end += 1

            # 提取数字部分并转换为整数
            rank = int(line[digit_start:digit_end])
    # if "sending in line" and "rank" in line:

    return rank

def addr_to_node(addr):
    if addr == 'a484':
        node = 1
    elif addr == 'a685':
        node = 2
    elif addr == '9787':
        node = 3
    elif addr == '9388':
        node = 4
    elif addr == '9889':
        node = 5
    elif addr == '9287':
        node = 6
    elif addr == 'b184':
        node = 7
    elif addr == 'a887':
        node = 8
    elif addr == 'b885':
        node = 9
    elif addr == '9387':
        node = 10
    elif addr == '8984':
        node = 11
    elif addr == '9588':
        node = 12
    elif addr == 'b384':
        node = 13
    elif addr == 'b187':
        node = 14
    elif addr == '9488':
        node = 15
    elif addr == '9385':
        node = 16
    elif addr == 'b585':
        node = 17
    elif addr == 'a587':
        node = 18
    elif addr == '9083':
        node = 19
    elif addr == 'b786':
        node = 20
    elif addr == 'a385':
        node = 21
    elif addr == 'a488':
        node = 22
    elif addr == 'a984':
        node = 23
    elif addr == '9084':
        node = 24
    elif addr == 'a187':
        node = 25
    elif addr == 'b685':
        node = 26
    elif addr == 'a185':
        node = 27
    elif addr == 'a586':
        node = 28
    elif addr == 'a284':
        node = 29
    elif addr == 'b086':
        node = 30
    elif addr == 'a885':
        node = 31
    elif addr == 'b287':
        node = 32
    elif addr == 'b286':
        node = 33
    elif addr == 'a786':
        node = 34
    elif addr == 'a784':
        node = 35
    elif addr == '9184':
        node = 36
    elif addr == 'a386':
        node = 37
    elif addr == '9589':
        node = 38
    elif addr == 'a184':
        node = 39
    elif addr == '9885':
        node = 41
    elif addr == 'b186':
        node = 42
    elif addr == '9285':
        node = 43
    elif addr == 'a684':
        node = 44
    elif addr == 'b385':
        node = 45
    elif addr == '9985':
        node = 46
    elif addr == 'a487':
        node = 47
    elif addr == '9789':
        node = 48
    elif addr == 'a186':
        node = 49
    elif addr == 'b586':
        node = 50
    elif addr == 'a585':
        node = 51
    elif addr == '9689':
        node = 52
    elif addr == '9890':
        node = 53
    elif addr == '9788':
        node = 54
    elif addr == 'b486':
        node = 55
    elif addr == 'a288':
        node = 56
    elif addr == '9986':
        node = 57
    elif addr == 'a788':
        node = 58
    elif addr == '9586':
        node = 59
    elif addr == 'a686':
        node = 60
    else :
        node = int(addr,16)
    return node


def find_source(line):
    src = '-'
    if "received" in line and "from" in line and 'EB' not in line:
        words = line.split()  # 将字符串按空格分割成单词列表
        index_of_from = words.index("from")  # 找到 "to" 在列表中的索引
        word_after_from = words[index_of_from + 1]  # 获取 "to" 后面的单词
        word_after_from = word_after_from.replace(',', '')
        if ":" in word_after_from:
            node=addr_to_node(word_after_from.split(":")[-1])
            src = int(node)
        else:
            node = addr_to_node(word_after_from.split(".")[-1])
            src = int(node)
    return src


def find_dest(line):
    dst = '-'
    if ("sending" in line or "sent" in line or "send" in line) and "DIS" not in line and "to" in line:
        words = line.split()  # 将字符串按空格分割成单词列表
        index_of_to = words.index("to")  # 找到 "to" 在列表中的索引
        word_after_to = words[index_of_to + 1]  # 获取 "to" 后面的单词
        word_after_to = word_after_to.replace(',', '')
        if ":" in word_after_to:
            node = addr_to_node(word_after_to.split(":")[-1])
            dst = int(node)
        else:
            node = addr_to_node(word_after_to.split(".")[-1])
            dst = int(node)
    return dst


def find_version(line):
    version = '-'
    if "version" in line and "received" in line:
        words = line.split()  # 将字符串按空格分割成单词列表
        index_of_to = words.index("version")  # 找到 "to" 在列表中的索引
        word_after_to = words[index_of_to + 1]  # 获取 "to" 后面的单词
        version = word_after_to.replace(',', '')
    return version



# 文件路径
file_path = r'logfile\DFA_1_malicious_nodes_FITIOT.log'



def process_file_chunk(chunk):
    df_chunk = pd.DataFrame(columns=['Time', 'NodeNumber', 'Source', 'Destination', 'EB', 'DIO', 'DIS',
                                     'DAO', 'DAO_ACK', 'packet', 'DIO_interval', 'DIS_interval', 'DIO_rank',
                                     'DIO_count', 'DIS_count', 'Version', 'Multicast', 'Unicast', 'Node_type',
                                     'Attack_type', 'data_packet', 'control_packet'])
    malicious = [5]
    attack_type = 'VNA'

    last_dis_time = {}
    last_dio_time = {}
    n = 0
    t_start = 0

    dio_interval = {}
    dis_interval = {}
    dis_count = {}
    dio_count = {}
    st_time=None

    for line in chunk:
        att = 0
        att_ty = '-'
        data = 0
        control = 0
        msg_ty = msg_type(line)
        if np.sum(msg_ty) != 0:
            node, time,st_time = sperate(line, True,st_time)
            if n == 0:
                t_start = time
                n = 1
            if time - t_start >= 300000:
                dio_count[node] = 0
                dis_count[node] = 0
                t_start = time

            dio_interval[node] = '-'
            dis_interval[node] = '-'
            rank = find_rank(line)
            if node not in dio_count:
                dio_count[node] = 0
            if node not in dis_count:
                dis_count[node] = 0

            if "sending" in line and "DIO" in line:
                if node in last_dio_time:
                    interval = time - last_dio_time[node]

                    dio_interval[node] = interval

                last_dio_time[node] = time

                dio_count[node] = dio_count[node] + 1

            if "sending" in line and "DIS" in line:
                if node in last_dis_time:
                    interval = time - last_dis_time[node]

                    dis_interval[node] = interval

                last_dis_time[node] = time

                dis_count[node] = dis_count[node] + 1

            src = find_source(line)
            dst = find_dest(line)

            version = find_version(line)

            if node in malicious:
                att = 1
                att_ty = attack_type

            if msg_ty[5, 0] == 0:
                control = 1
            if "app" in line:
                data = 1

            # 新增一行数据
            new_row = {'Time': time, 'NodeNumber': node, 'Source': src, 'Destination': dst, 'EB': int(msg_ty[0, 0]), \
                       'DIO': int(msg_ty[1, 0]), 'DIS': int(msg_ty[2, 0]), 'DAO': int(msg_ty[3, 0]), \
                       'DAO_ACK': int(msg_ty[4, 0]), 'packet': int(msg_ty[5, 0]), 'DIO_interval': dio_interval[node], \
                       'DIS_interval': dis_interval[node], 'DIO_rank': rank, 'DIO_count': dio_count[node], \
                       'DIS_count': dis_count[node], 'Version': version, 'Multicast': int(msg_ty[6, 0]),
                       'Unicast': int(msg_ty[7, 0]), \
                       'Node_type': att, 'Attack_type': att_ty, 'data_packet': data, 'control_packet': control}

            # 将新行添加到表格数据中
            df_chunk = pd.concat([df_chunk, pd.DataFrame([new_row])], ignore_index=True)

    return df_chunk

if __name__ == '__main__':
    with open(file_path, "r", encoding='utf-8') as f:
        lines = f.readlines()

    # 设置最大进程数
    max_processes = 8

    # 将数据分割成多个块，每个块分配给一个进程处理
    chunk_size = len(lines) // max_processes
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

    # 使用进程池并行处理每个块
    with Pool(processes=max_processes) as pool:
        result_chunks = pool.map(process_file_chunk, chunks)

    # 将处理结果合并到一个整体的 DataFrame
    df_combined = pd.concat(result_chunks, ignore_index=True)

    # 读取现有的 Excel 文件（如果存在）
    try:
        df_existing = pd.read_excel('data.xlsx')
    except FileNotFoundError:
        df_existing = pd.DataFrame()

    # 将新数据合并到现有数据中
    df_combined = pd.concat([df_existing, df_combined], ignore_index=True)

    # 将更新后的表格数据写入 Excel 文件（mode='a' 表示追加模式）
    output_excel_path = 'data.xlsx'  # 请替换为实际输出文件路径
    df_combined.to_excel(output_excel_path, index=False)
