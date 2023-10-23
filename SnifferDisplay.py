from tkinter import constants, Text, Scrollbar, Button, Toplevel, Label
from Packet_Info import Packet_Info
from utils import *

class DisplayBoard():
    def __init__(self, frame, packetList):
            
        self.packetList=packetList
        self.frame=frame
        self.textboxes=[]
        
        self.scroll= Scrollbar(frame, command=self.scroll_multiple)
        self.scroll.grid(row=1, column=4, sticky='ns')
        
        #labels for categories
        labels=['ID', 'SRC', 'DST', 'PROTOCOL']
        
        for col, label_text in enumerate(labels):
            label = Label(frame, text=label_text, background=TEXTBOX_BG, foreground='white')
            label.grid(row=0, column=col)
            self.create_textbox(col)
        
        self.bind_events()
        
    def create_textbox(self, index):
        textbox=Text(self.frame, background=TEXTBOX_BG, font=('imperial', 12), foreground='white',
                        yscrollcommand=self.scroll, state=constants.DISABLED)
        textbox.grid(row=1, column=index, padx=5, pady=5, sticky='nsew')
        self.frame.columnconfigure(index, weight=1)  # Allow column to resize
        self.textboxes.append(textbox) 
        
    def bind_events(self):
        for textbox in self.textboxes:
            textbox.bind("<MouseWheel>", self.mouse_scroll_multiple)
            textbox.bind("<Button-1>", lambda _, tb=textbox: self.valid_packet(tb.index(constants.CURRENT)))

    def mouse_scroll_multiple(self, event):
                for textbox in self.textboxes:
                    textbox.config(state=constants.NORMAL)
                    textbox.yview_scroll(-1*(event.delta//120), 'units')
                    textbox.config(state=constants.DISABLED)

    def scroll_multiple(self, *args):
            for textbox in self.textboxes:
                textbox.yview(*args)          
    
    def valid_packet(self, line_char_index):
        line_index = int(line_char_index.split('.')[0])
        if self.textboxes[0].get('1.0', constants.END)=='':
            pass
        try:
            packet=self.packetList[line_index]
            self.packet_info(packet, line_index)
        except:
            pass
    
    def packet_info(self, packet, line_index):
        packet_page=Toplevel(self.frame)
        packet_page.title(f'Packet {line_index}')
        packet_page.geometry('600x600')
        packet_page.resizable(False, False)
        
        packet=Packet_Info(packet)
            
        info_page=Text(packet_page, state=constants.DISABLED)
        info_page.pack(padx=20, pady=20)
        info_page.place(x=5, y=50, width=590, height=540)
        
        buttons_y=5
        buttons_x=25
        
        
        create_button(packet_page, text='Ethernet', x=buttons_x, y=buttons_y, width=100, height=40,
                             command=lambda packet=packet: self.print_layer_info(packet, packet.layer_index['DATA_LINK'], info_page))
        
        layer3_button=Button(packet_page, text='Network layer', 
                             command=lambda packet=packet: self.print_layer_info(packet, packet.layer_index['NETWORK'], info_page))
        layer3_button.pack(padx=20, pady=20)
        layer3_button.place(x=buttons_x+105, y=buttons_y, width=100, height=40)
        
        if packet.layer_info[packet.layer_index['TRANSPORT']]:
            create_button(packet_page, text='Transport layer', x=buttons_x+210, y=buttons_y, width=100, height=40,
                                 command=lambda packet=packet: self.print_layer_info(packet, packet.layer_index['TRANSPORT'], info_page))
            if packet.layer_info[packet.layer_index['APPLICATION']]:
                create_button(packet_page, text='Application layer', x=buttons_x+315, y=buttons_y, width=100, height=40,
                                 command=lambda packet=packet: self.print_layer_info(packet, packet.layer_index['APPLICATION'], info_page))
        elif packet.layer_info[packet.layer_index['ICMP']]:
            create_button(packet_page, text='ICMP',x=buttons_x+210, y=buttons_y, width=100, height=40,
                                 command=lambda packet=packet: self.print_layer_info(packet, packet.layer_index['ICMP'], info_page))
            
    
    def print_layer_info(self, packet: Packet_Info, layer: int, textbox: Text):
        textbox.config(state=constants.NORMAL)
        textbox.delete('1.0', constants.END)
        
        textbox.insert('1.0', packet.layer_info[layer])
        
        textbox.config(state=constants.DISABLED)
                
        
    def print_results(self, id: int, src: str, dst: str, protocol: str):
        for i, textbox in enumerate(self.textboxes):
            textbox.config(state=constants.NORMAL)
            textbox.insert(constants.END, f'{id if i == 0 else src if i == 1 else dst if i == 2 else protocol}\n')
            textbox.config(state=constants.DISABLED)