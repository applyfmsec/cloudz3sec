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


    x_data, y_data, z_data = np.loadtxt('z3_string_re_wc_results.csv', delimiter=',', unpack=True)
    

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


def plot_enum_with_stats():

    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('z3_enum_results.csv', delimiter=',', unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    q_impy_p_means = []
    q_impy_p_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        qp_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            qp_temp.append(q_imply_p[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

        q_impy_p_means.append(np.mean(qp_temp))
        q_impy_p_stds.append(np.std(qp_temp))
    # create plots of means with error bars based on std
    plt.title('Enum Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    s4 = plt.scatter(data_size_vals, q_impy_p_means, color='c')
    plt.errorbar(data_size_vals,q_impy_p_means, yerr=q_impy_p_stds, fmt='o', color='c')
    plt.legend([s1, s2, s3, s4], ['Data load', 'SMT Encoding', 'P => Q', 'Q => P'])
    
    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")
    
    # output and save
    plt.show()
    plt.savefig('z3_enum_perf_stats.png')


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


def plot_string_re_wc_stats():
    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

    # create plots of means with error bars based on std
    plt.title('StringRe With Wildcard Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    plt.legend([s1, s2, s3], ['Data load', 'SMT Encoding', 'P => Q'])

    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")
    
    # output and save
    plt.show()
    plt.savefig('z3_string_wc_perf_stats.png')

    
