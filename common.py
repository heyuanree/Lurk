# coding:utf-8

from subprocess import Popen
import logger
import os


def locate_file_dir(file_name, dir_name=os.getcwd()):
    """
    :param file_name:
    :param dir_name:
    :return: file_dir
    """
    for root, dirs, files in os.walk(dir_name):
        for name in files:
            if file_name == name:
                return root
    return None


def locate_file(file_name, dir=os.getcwd()):
    """
    :param file_name:
    :param dir:
    :return: file_dir/file_name
    """
    root = locate_file_dir(file_name, dir)
    if root:
        return os.path.join(root, file_name)
    else:
        return None


def locate_dir(dir_name, dir=os.getcwd()):
    """
    :param dir_name:
    :param dir:
    :return: dir_dir/dir_name
    """
    for root, dirs, files in os.walk(dir):
        for dir in dirs:
            if dir == dir_name:
                return os.path.join(root, dir)
    return None


def clean(dir_name):
    dir_name = locate_dir(dir_name)
    logger.info(dir_name)
    for root, dirs, files in os.walk(dir_name):
        for name in files:
            remove_file = "{}".format(os.path.join(root, name))
            logger.info("Clean file {}".format(remove_file))
            os.remove(remove_file)


def nasm_build(filename):
    """
    :param filename: filename should be xxx.asm
    :return: path of file xxx.bin
    """
    file_path = locate_file(filename)
    bin_name = filename.split('.')[0] + '.bin'
    if file_path:
        src_input = file_path
        bin_output = os.path.normpath(os.path.join(locate_file_dir(filename), bin_name))
        p = Popen(["nasm", "-f bin", "-O3", "-o {}".format(bin_output), "{}".format(src_input)])
        p.wait()
    else:
        logger.error("nasm_build find no filename: {}.".format(filename))
    return bin_name
