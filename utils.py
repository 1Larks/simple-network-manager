from tkinter import Label, Button, Text
from tkinter import END, NORMAL, DISABLED

BACKGROUND_COLOR='#3A7575'
TEXTBOX_BG='#5F9EA0'
TEXTBOX_FONT=('imperial', 12)

protocol_table={
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP', 
    58: 'ICMPv6'
}

def create_label(**kw) -> Label:
        label=Label(kw['root'], text=kw['text'], background=kw['background'], foreground=kw['foreground'])
        if 'font' in kw:
            label['font']=kw['font']
        label.place(x=kw['x'], y=kw['y'], width=kw['width'], height=kw['height'])
        return label
    
def create_button(**kw) -> Button:
    button=Button(kw['root'], text=kw['text'], command=kw['command'])
    if 'anchor' in kw:
        button['anchor']=kw['anchor']
    if 'background' in kw:
        button['background']=kw['background']
    if 'foreground' in kw:
        button['foreground']=kw['foreground']
    if 'font' in kw:
        button['font']=kw['font']
    button.place(x=kw['x'], y=kw['y'], width=kw['width'], height=kw['height'])
    return button

def create_results_textbox(**kw) -> Text:
    results=Text(kw['root'], background=TEXTBOX_BG, font=TEXTBOX_FONT, foreground='white', state=DISABLED)
    results.place(x=kw['x'], y=kw['y'], width=kw['width'], height=kw['height'])
    return results

def write_to_textbox(textbox: Text, text: str):
    textbox['state']=NORMAL
    textbox.insert(END, text)
    textbox['state']=DISABLED

