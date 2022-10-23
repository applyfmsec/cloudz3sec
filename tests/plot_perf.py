import numpy as np
from matplotlib import pyplot as plt
import csv
#

def plot_enum():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []


    #x_data, y_data, z_data = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    s4 = plt.scatter(data_size, q_imply_p,c='c')
    plt.legend([s1, s2, s3, s4], ['Data load', 'SMT Encoding', 'P => Q', 'Q => P'])
    #plt.title('StringRe with wildcard')
    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()

#plot_enum()

def plot_string_re_wc():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    #q_imply_p = []

    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    plt.legend([s1,s2,s3],['Data load','SMT Encoding','P => Q' ])
    #plt.scatter(data_size, q_imply_p,c='c')
    #plt.title('StringRe with wildcard')
    plt.title('StringRe with WildCard Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()
#plot_string_re_wc()