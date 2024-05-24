import zlib
# 解压文件或数据
def decompress_data(zip_file, new_file):
    zip_file = open(zip_file, 'rb')
    new_file = open(new_file, 'wb')
    decompress = zlib.decompressobj()
    data = zip_file.read(1024)
    while data:
        new_file.write(decompress.decompress(data))
        data = zip_file.read(1024)
    new_file.write(decompress.flush())
    zip_file.close()
    new_file.close()
 
 
if __name__ == '__main__':
    decompress_data(r"D:\CTFtools\Reverse\信息收集\ExplorerSuite_ha\dump", r"D:\CTFtools\Reverse\信息收集\ExplorerSuite_ha\new")
    print('end!')