import tkinter as tk
from tkinter import ttk
from tkinter import font

import base64


root = tk.Tk()
root.title("base64")
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

tk.font.Font(name="heading",size=100,weight="bold")

mainframe = ttk.Frame(root,padding=8,borderwidth=10,relief="groove")
mainframe.grid(sticky="nwes")
mainframe.columnconfigure(0,weight=1)
mainframe.columnconfigure(1,weight=1)
mainframe.rowconfigure(0,weight=1)


def encoding():
	mode=enc_mode.get()
	if (mode != "utf-8"):
		if mode == "binary":
			wordsize=8
			base=2
		else:
			wordsize=2
			base=16
		strinp = encoder_text.get("1.0",tk.END).split()
		if ((len(strinp[-1])) != wordsize ):
			encoder_text['fg']="red"
			encoutp.set("base64 works on 8-bit bytes \nkindly input a 8-bit bytes data")
			encoder_text.bind("<ButtonPress>" , lambda e: encoder_text.configure(fg="black"))
			return "break"
		intinp = [int(x,base=base) for x in strinp]
		byteinp = bytes(intinp)
		encoutp.set(base64.b64encode(byteinp).decode("ascii"))
	else:
		strinp = encoder_text.get("1.0","end-1c")
		byteinp = strinp.encode('ascii')
		byteoutp = base64.b64encode(byteinp)
		encoutp.set(byteoutp.decode('ascii'))

def byte_format(event):
	mode=enc_mode.get()
	inp = event.widget.get("1.0",tk.END)
	if event.char == "\b":
		event.widget.delete("end-2c")
		if event.widget.get("end-2c") == " " :
			event.widget.delete("end-2c")
		return "break"
	if (mode=="binary"):
		sp_size=9
	elif (mode=="hexadecimal"):
		sp_size=3
	if (mode!="utf-8" and len(inp)%sp_size == 0):
		event.widget.insert(tk.END," ")
	char_list=[]
	if (mode=="binary"):
		char_list = ["0","1"]
	elif (mode=="hexadecimal"):
		char_list = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
	if (event.char in char_list) or (mode=="utf-8"):
		event.widget.insert(tk.END,event.char)
	return "break"




encoder = ttk.Frame(mainframe,padding=30,relief="sunken")
encoder.grid(column=0,sticky="nwes")

ttk.Label(encoder,text="Encoder",font="heading").grid(row=0,column=0,pady=(0,20))
ttk.Label(encoder,text="Text to encode:").grid(row=1,column=1)
ttk.Label(encoder,text="Encoded output:").grid(row=3,column=1,pady=100)

encoder_text = tk.Text(encoder,width=60)
encoder_text.grid(row=1,column=2,columnspan=3)
encoder_text.bind("<KeyPress>",byte_format)

def flush(var,index,mode):
	encoder_text.delete("1.0",tk.END)

enc_mode = tk.StringVar()
enc_mode.trace_variable("w",flush)
enc_mode.set("binary")
enc_binary = ttk.Radiobutton(encoder,text="binary",variable=enc_mode,value="binary")
enc_binary.grid(row=2,column=2)
enc_hexadecimal = ttk.Radiobutton(encoder,text="hexadecimal",variable=enc_mode,value="hexadecimal")
enc_hexadecimal.grid(row=2,column=3)
enc_utf8 = ttk.Radiobutton(encoder,text="utf-8",variable=enc_mode,value="utf-8")
enc_utf8.grid(row=2,column=4)


encoutp=tk.StringVar()
encoder_label = ttk.Label(encoder,textvariable=encoutp)
encoder_label.grid(row=3,column=2,pady=20,columnspan=3) 

ttk.Button(encoder,command=encoding,text="encode").grid(row=5,column=3)


def decoding(var=None,index=None,mode=None):
	strinp = decoder_text.get("1.0",tk.END)
	bininp = strinp.encode('ascii')
	try:
		binoutp = base64.b64decode(bininp)
	except:
		decoder_text['fg']="red"
		decoutp.set("invalid base64 data")
		decoder_text.bind("<ButtonPress>" , lambda e: decoder_text.configure(fg="black"))
		return "break"
	mode=dec_mode.get()
	if (mode != "utf-8"):
		if (mode=="binary"):
			ftype = "08b"
		else:
			ftype = "02x"
		x=[]
		for i in binoutp:
			x.append(format(i,ftype))
		decoutp.set(" ".join(x))
	else:
		decoutp.set(binoutp.decode('utf-8'))

decoder = ttk.Frame(mainframe,padding=30,relief="sunken")
decoder.grid(row=0,column=1,sticky="nwes")
ttk.Label(decoder,text="Decoder",font="heading").grid(row=0,column=0,pady=(0,20))
ttk.Label(decoder,text="Text to decode:").grid(row=1,column=1)
ttk.Label(decoder,text="Decoded output:").grid(row=3,column=1,pady=100)

decoder_text = tk.Text(decoder,width=60)
decoder_text.grid(row=1,column=2,columnspan=3)

decoutp=tk.StringVar()
decoder_label = ttk.Label(decoder,textvariable=decoutp)
decoder_label.grid(row=3,column=2,pady=20,columnspan=3) 

dec_mode = tk.StringVar()
dec_mode.set("binary")
dec_mode.trace_variable("w",decoding)
dec_binary = ttk.Radiobutton(decoder,text="binary",variable=dec_mode,value="binary")
dec_binary.grid(row=4,column=2)
dec_hexadecimal = ttk.Radiobutton(decoder,text="hexadecimal",variable=dec_mode,value="hexadecimal")
dec_hexadecimal.grid(row=4,column=3)
dec_utf8 = ttk.Radiobutton(decoder,text="utf-8",variable=dec_mode,value="utf-8")
dec_utf8.grid(row=4,column=4)

ttk.Button(decoder,command=decoding,text="decode").grid(row=5,column=3,pady=40)


root.mainloop()