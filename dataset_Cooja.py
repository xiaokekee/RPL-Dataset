——import pandas as pd
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


def find_source(line):
    src = '-'
    if "received" in line and "from" in line and 'EB' not in line:
        words = line.split()  # 将字符串按空格分割成单词列表
        index_of_from = words.index("from")  # 找到 "to" 在列表中的索引
        word_after_from = words[index_of_from + 1]  # 获取 "to" 后面的单词
        word_after_from = word_after_from.replace(',', '')
        if ":" in word_after_from:
            src = int(word_after_from.split(":")[-1], 16)
        else:
            src = int(word_after_from.split(".")[-1], 16)
    return src


def find_dest(line):
    dst = '-'
    if ("sending" in line or "sent" in line or "send" in line) and "DIS" not in line and "to" in line:
        words = line.split()  # 将字符串按空格分割成单词列表
        index_of_to = words.index("to")  # 找到 "to" 在列表中的索引
        word_after_to = words[index_of_to + 1]  # 获取 "to" 后面的单词
        word_after_to = word_after_to.replace(',', '')
        if ":" in word_after_to:
            dst = int(word_after_to.split(":")[-1], 16)
        else:
            dst = int(word_after_to.split(".")[-1], 16)
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
file_path = r'node\SHA-1.testlog'
#file_path = 'DFA-1.testlog'


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

    for line in chunk:
        att = 0
        att_ty = '-'
        data = 0
        control = 0
        msg_ty = msg_type(line)
        if np.sum(msg_ty) != 0:
            node, time = sperate(line, False)
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
    with open(file_path, "r") as f:
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
