import tkinter as tk
from tkinter import ttk
from Sniffer import Sniffer
from SnifferDisplay import DisplayBoard
from utils import *

class NetworkManagerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root=root
        self.root.title('Network Manager')
        self.root.geometry('900x700')
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        self.root.resizable(False, False)
        self.root['background'] = BACKGROUND_COLOR
        self.sniffer = Sniffer()
    
    #need fix
    def on_close(self):
        if not self.sniffer.stop:
            self.sniffer.stop_sniffing()
        self.root.destroy()
    
    def create_return_button(self):
        return create_button(root=self.root, text='Return', command=None, x=10, y=10, width=75, height=50,
                            font=(FONT_NAME, 14), background='#FAEDE3', foreground='#28282B')

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def toggle_sniffing_button_click(self, button: tk.Button, display: DisplayBoard):
        if self.sniffer.stop:
            self.sniffer.start_sniffing_thread()
            for box in display.textboxes:
                box['state']= tk.NORMAL
                box.delete('1.0', tk.END)
                box['state']= tk.DISABLED
            button['text']='Stop sniffing'
        else:
            self.sniffer.stop_sniffing()
            button['text']='Start sniffing'
    
    def toggle_port_scanning_button_click(self, button: tk.Button, textbox: tk.Text, start, end, rangeEntries):
        if self.sniffer.stop:
            for entry in rangeEntries:
                entry['state']=tk.DISABLED
            textbox['state']= tk.NORMAL
            textbox.delete('1.0', tk.END)
            textbox['state']= tk.DISABLED
            self.sniffer.port_syn_scan(start, end, textbox)
            button['text']='Stop scanning'
        else:
            for entry in rangeEntries:
                entry['state']=tk.NORMAL
            self.sniffer.stop_sniffing()
            button['text']='Start scanning'
    
    def main_menu(self):
        self.clear_root()
        if not self.sniffer.stop:
            self.sniffer.stop_sniffing()
        # Welcome label
        create_label(root=self.root, text='Welcome to Larks\' network managment system.\n\nPlease select a network interface.', 
                                        font=(FONT_NAME, 24), background=BACKGROUND_COLOR, foreground='#FAEDE3', 
                                        x=50, y=50, width=800, height=125)
        
        # Combo box for selecting the network interface
        iface_CB=ttk.Combobox(self.root, state='readonly', values=self.sniffer.network_interfaces, font=(FONT_NAME, 16))
        iface_CB.pack()
        iface_CB.place(x=150, y=250, width=600, height=50)
        
        # Choose network interface
        def valid_interface():
            selected_iface=iface_CB.get()
            if selected_iface=='':
                pass
            else:
                self.sniffer.set_network_iface(selected_iface)
                self.sniffing_options()
            
        create_button(root=self.root, text='Continue', command=valid_interface, 
                                font=(FONT_NAME, 14), background='#FAEDE3', foreground='#28282B', 
                                x=400, y=450, width=100, height=75)
        create_button(root=self.root, text='Port scan', font=(FONT_NAME, 18), background='#FAEDE3', foreground='#28282B', 
                           x=350, y=550, width=200, height=50, command=self.port_scan)
    
    def sniffing_options(self):
        self.clear_root()
        #Init return button
        return_button=self.create_return_button()
        return_button['command']=self.main_menu
        
        #Show the selected interface
        create_label(root=self.root, text=f'The selected interface: {self.sniffer.NETWORK_IFACE}', font=(FONT_NAME, 24),
                            background=BACKGROUND_COLOR, foreground='white', x=120, y=10, width=550, height=50, anchor=tk.W)
        
        #General sniffing button
        create_button(root=self.root, text='Sniff all traffic',  font=(FONT_NAME, 18), background='#FAEDE3', foreground='#28282B',
                           command=self.sniff_page, x=350, y=150, width=200, height=50)
        
        #Sniff different devices button
        create_button(root=self.root, text='Sniff devices',  font=(FONT_NAME, 18), background='#FAEDE3', foreground='#28282B', 
                           x=350, y=250, width=200, height=50, command=self.sniff_from_devices)
      
    def sniff_page(self, filter= None): # filter example: src host 192.168.1.24
        self.clear_root()
        
        #Init return button
        return_button=self.create_return_button()
        return_button.config(command=self.sniffing_options)
        
        display_frame=tk.Frame(self.root, background=TEXTBOX_BG)
        display_frame.pack(padx=50, pady=50)
        display_frame.place(x=40, y=132, width=800 , height=435)
        
        display=DisplayBoard(display_frame)
        
        self.sniffer.set_network_iface(self.sniffer.NETWORK_IFACE)
        self.sniffer.set_display(display)
        if filter:
            self.sniffer.set_filter(filter)
        
        #Toggle sniffing button
        toggle_sniffing_button=create_button(root=self.root, text='Start sniffing', command=None,
                                font=(FONT_NAME, 18), background='#FAEDE3', foreground='#28282B', x=350, y=600, width=200, height=50)
        toggle_sniffing_button['command']=lambda: self.toggle_sniffing_button_click(toggle_sniffing_button, display)
    
    def sniff_from_devices(self):
        self.clear_root()
        return_button=self.create_return_button()
        return_button['command']=self.main_menu
        results=create_results_textbox(root=self.root, x=90, y=132, width=700, height=435)
        devices=self.sniffer.get_network_entities()
        for device in devices:
            results.insert(tk.END, 'address: {ip}, mac: {mac}, hostname: {hostname}'.format(**device))
        results['state']=tk.DISABLED
        print('done')
    
    def port_scan(self):
        self.clear_root()
        ip=self.sniffer.get_machine_ip()
        return_button=self.create_return_button()
        return_button['command']=self.main_menu
        results=create_results_textbox(root=self.root, x=90, y=132, width=700, height=435)
        
        range_selection_frame=tk.Frame(self.root, background=BACKGROUND_COLOR)
        range_selection_frame.pack()
        range_selection_frame.place(x=150, y=15, width=550, height=40)
        
        def digits_only(P):
            return str.isdigit(P) or P == ""
                
        validate = (self.root.register(digits_only), '%P')

        create_label(root=range_selection_frame, text='start port:', 
                                        font=(FONT_NAME, 13), background=BACKGROUND_COLOR, 
                                        foreground='#FAEDE3', x=0, y=0, width=75, height=40)
        
        range_selection1=create_entry(root=range_selection_frame, validatecommand=validate, 
                                      validate='key', x=75, y=0, width=75, height=40, text='1')
        
        create_label(root=range_selection_frame, text='end port:', 
                                        font=(FONT_NAME, 13), background=BACKGROUND_COLOR, 
                                        foreground='#FAEDE3', x=150, y=0, width=75, height=40)
        
        range_selection2=create_entry(root=range_selection_frame, validate='key', validatecommand=validate,
                                  x=225, y=0, width=75, height=40, text='1024')

        toggle_scan_button=create_button(root=self.root, text='Start scanning', command=None, font=(FONT_NAME, 18), 
                                         background='#FAEDE3', foreground='#28282B', x=350, y=600, width=200, height=50)
        
        toggle_scan_button['command']=lambda: self.toggle_port_scanning_button_click(toggle_scan_button, results, 
                                                                                     int(range_selection1.get()), 
                                                                                     int(range_selection2.get()), 
                                                                                     (range_selection1, range_selection2))
        
        create_label(root=range_selection_frame, text='IP address', 
                                        font=(FONT_NAME, 13), background=BACKGROUND_COLOR, foreground='#FAEDE3', 
                                        x=300, y=0, width=75, height=40)
        
        ip_entry=create_entry(root=range_selection_frame, text=ip, x=375, y=0, width=75, height=40)
        
    def start(self):
        self.main_menu()
    
if __name__=='__main__':
    root=tk.Tk()
    app = NetworkManagerApp(root)
    app.start()
    root.mainloop()