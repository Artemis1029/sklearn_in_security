import re
import os
from urllib import unquote

import pandas as pd
from sklearn import datasets, metrics, model_selection, svm
from sklearn.externals import joblib
from sklearn.metrics import classification_report

Base64_pattern = ""
dom_spcstr_pattern = re.compile("(%0A)|(%0D)")
char_conf_pattern = re.compile("['\"]\+[\"']")
space_pattern = re.compile("\+|(%20)|\n|\r")
split_pattern = re.compile("[\/?&]")
evil_char_pattern = re.compile("[<>,\'\"/]")
with open("data/dom.txt", "r") as f:
    dom = f.readlines()
dom = "(" + ")|(".join(dom).replace("\r\n", "") + ")"
dom += "|(<script)|(src=)|(javascript:)"
evil_word_pattern1 = re.compile(dom)
evil_word_pattern2 = re.compile("(javascript:)|(eval)|\
    (fetch)|($.get)|($.post)|(xmlhttprequest)|(cookie)\
        |(document)|(src=)")

matrix = []
is_xss = []


def trychangecode(lists, count):
    string = ""
    lists.reverse()
    while lists:
        data = lists.pop()
        data = unquote(data)
        if char_conf_pattern.search(data):
            count += 1
            data = char_conf_pattern.sub("", data)
        string += data
        string += " "
    return string, count

def data_clean(filename, xss=1):
    datas = open(filename, "r")
    datas = datas.readlines()
    string = ""
    confusion = ""
    while datas:
        count = 0
        data = datas.pop()
        if dom_spcstr_pattern.search(data, re.IGNORECASE):
            count += 1
            data = dom_spcstr_pattern.sub("", data, re.IGNORECASE)
        data = space_pattern.sub("", data)
        if data == "/":
            data = "_"
        data = split_pattern.split(data)
        # a bug weith split using re.IGNORECAS
        (data, count) = trychangecode(data, count)
        matrix.append([
            get_len(data), 
            get_evil_char(data),
            get_evil_word1(data),
            get_evil_word2(data),
            count,
            xss,
            ])
        is_xss.append(
            xss
        )
        string = "%s\n%s" % (data, string)
        confusion = "%d\n%s" % (count, confusion)
    with open("data/temp.txt", "w") as f:
        f.write(string)



def get_len(uri):
    return max([len(i) for i in uri.split(" ")])

def get_url_count(uri):
    pass

def get_evil_char(uri):
    return len(evil_char_pattern.findall(uri))

def get_evil_word1(uri):
    return len(evil_word_pattern1.findall(uri,re.IGNORECASE))

def get_evil_word2(uri):
    return len(evil_word_pattern2.findall(uri,re.IGNORECASE))


def do_metrics(y_test,y_pred):
    print "metrics.accuracy_score:"
    print metrics.accuracy_score(y_test, y_pred)
    print "metrics.confusion_matrix:"
    print metrics.confusion_matrix(y_test, y_pred)
    print "metrics.precision_score:"
    print metrics.precision_score(y_test, y_pred)
    print "metrics.recall_score:"
    print metrics.recall_score(y_test, y_pred)
    print "metrics.f1_score:"
    print metrics.f1_score(y_test,y_pred)


def main():
    if not os.path.exists("data/matrix.csv"):
        filename_xss = "data/xss-200000.txt"
        data_clean(filename_xss, 1)
        filename_good = "data/good-xss-200000.txt"
        data_clean(filename_good, 0)
        global matrix
        matrix = pd.DataFrame(matrix)
        matrix.to_csv('data/matrix.csv')
    else:
        matrix = pd.read_csv("data/matrix.csv")
    is_xss = matrix[["5"]]
    matrix = matrix[["0","1","2","3","4"]]
    # start
    x_train, x_test, y_train, y_test = model_selection.train_test_split(matrix, is_xss, test_size=0.4, random_state=0)
    clf = svm.SVC(kernel='rbf', C=3).fit(x_train, y_train)
    y_pred = clf.predict(x_test)
    do_metrics(y_test, y_pred)
    joblib.dump(clf,"xss-svm-module.m")


def continue_():
    clf = joblib.load("xss-svm-module.m")
    filename_log = "data/load_data.txt"
    global matrix
    matrix = []
    data_clean(filename_log , 0)
    matrix = pd.DataFrame(matrix[::-1])
    matrix = matrix[[i for i in range(5)]]
    output = clf.predict(matrix)
    with open(filename_log) as f:
        data = pd.DataFrame(f.readlines())
    data_is_xss = data[output==1]
    data_is_xss.to_csv("result/xss.txt")
    data_not_xss = data[output==0]
    data_not_xss.to_csv("result/nor.txt")
    


main()
# continue_()
