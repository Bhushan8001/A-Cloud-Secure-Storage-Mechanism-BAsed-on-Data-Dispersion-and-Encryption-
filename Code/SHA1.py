# from flask import *
# if request.method == 'POST':
#     filedata = request.files['filedata']
#     print(filedata.filename)
#     x = filedata.read()
#     sql = "select * from patients where Id='%s' and Name='%s'" % (m, n)
#     cur.execute(sql)
#     data = cur.fetchall()
#     db.commit()
#     symp = data[0][6]
#
#     datalen = int(len(x) / 2)
#     print(datalen, len(x))
#     g = 0
#     a = ''
#     b = ''
#     c = ''
#
#     for i in range(0, 2):
#         if i == 0:
#             a = x[g: datalen:1]
#             a = data.decode('utf-8')
#             print(a)
#             result = hashlib.sha1(a.encode())
#             hash1 = result.hexdigest()
#             print(hash1)
#             print("===================================")
#             # result = hashlib.sha1(a.encode())
#             # hash1 = result.hexdigest()
#             # print(hash1)
#             print("++++++++++++++++++++++++++")
#             # print(g)
#             # print(len(data))
#             # b = data[g: len(data):1]
#             # print(c)
#
#             print(g)
#             print(len(x))
#             c = x[datalen: len(x):1]
#             c = c.decode('utf-8')
#             print(c)
#             print("===================================")
#             print("*****************************")
#             result = hashlib.sha1(c.encode())
#             hash2 = result.hexdigest()
#             print(hash2)
#             print(m, n)
#             dat = data[0][-1]
#             from datetime import date
#
#             today = date.today()
#             try:
#                 sql = "INSERT INTO reports (slno,Name,Symptoms,FileData,HashA,HashB,StartDate,EndDate) VALUES (%s,%s,%s,AES_ENCRYPT(%s,'keys'),%s,%s,%s,%s)"
#                 val = (m, n, symp, x, hash1, hash2, dat, today)
#                 cur.execute(sql, val)
#                 db.commit()
#                 msg = "File Uploaded successfully"
#                 return render_template('addreport.html', m=m, n=n, msg=msg)
#             except:
#                 msg = "Each File Added only Once for a patient"
#                 return render_template('addreport.html', m=m, n=n, msg=msg)
# return render_template("dot.html")
"""
data=b'The server encountered an internal error or misconfiguration and was unable to complete your request.'
type(data)
Out[25]: bytes
import hashlib
result = hashlib.sha1(data.encode())
"""



"""
data=b'The server encountered an internal error or misconfiguration and was unable to complete your request.'
type(data)
Out[25]: bytes
import hashlib
result = hashlib.sha1(data.encode())
result
Out[31]: <sha1 HASH object @ 0x0000018B431E42D8>
hash1 = result.hexdigest()
hash1
Out[33]: '3deedb4935aff37547512c50aeddb9ff0d84e1a1'
"""