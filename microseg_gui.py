#!/usr/bin/env python
###################################################################################
#                           Written by Wei, Hang                                  #
#                          weihang_hank@gmail.com                                 #
###################################################################################
"""
This application helps to build a zero-trust environment that micro-segments
an existing EPG of an ACI. The segmentation is based on analytics from  AppDynamics
(It can also support manual pre-configuration)
"""
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
import cobra.mit.access
import cobra.mit.session
import cobra.mit.request
import cobra.model.pol
import cobra.model.fv
import cobra.model.vmm
import os
import time
from credentials import *
from appdata import *

# create a session and login ACI
requests.packages.urllib3.disable_warnings()
ls = cobra.mit.session.LoginSession(URL, LOGIN, PASSWORD)
md = cobra.mit.access.MoDirectory(ls)
md.login()


def Query_Objs(class_name, wcard_str):
    """
    This function is to return object list that matches the classname and wcard str
    """
    class_query = cobra.mit.request.ClassQuery(class_name)
    class_query.propFilter = 'wcard({}.dn, "{}")'.format(class_name, wcard_str)
    return md.query(class_query)


def get_tenant_list():
    """
    This function returns tenant name list
    """
    tenants = Query_Objs("fvTenant", "tn")
    tn_list = [""]
    for tn in tenants:
        tn_list.append(tn.name)
    return tn_list


def get_ap_list(_tenant):
    """
    This function returns Application Profile name list
    """
    aps = Query_Objs("fvAp", _tenant)
    ap_list = [""]
    for ap in aps:
        ap_list.append(ap.name)
    return ap_list


def get_epg_list(_tenant, _approfile):
    """
    This function returns EPG name list
    """
    epgs = Query_Objs("fvAEPg", "tn-" + _tenant + "/ap-" + _approfile)
    epg_list = [""]
    for epg in epgs:
        epg_list.append(epg.name)
    return epg_list


def test_input(_tenant, _aprofile, _epg):
    """
    This function tests if the args exist.
    """
    dn_query = cobra.mit.request.DnQuery("uni/tn-{}/ap-{}/epg-{}".format(_tenant, _aprofile, _epg))
    if not md.query(dn_query):
        tk.messagebox.showerror(title="Error",
                                message="We can't find your Base EPG {} in Tenant {} AppProfile {}!".format(_epg,
                                                                                                            _tenant,
                                                                                                            _epg))
        exit(1)


def readfile(filename):
    """
    This function is to read the file at current directory and convert it to python data
    """
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, filename)) as file:
        json_text = file.read()

    return json.loads(json_text)


def get_BDname(_tenant, _aprofile, _epg):
    """
    This function is to return bdname
    """
    objs = Query_Objs("fvRsBd", "uni/tn-{}/ap-{}/epg-{}".format(_tenant, _aprofile, _epg))
    return objs[0].tnFvBDName


def get_VMM(_tenant, _aprofile, _epg):
    """
    This function is to return the current VMM Domain's DN
    """
    objs = Query_Objs("fvRsDomAtt", "uni/tn-{}/ap-{}/epg-{}".format(_tenant, _aprofile, _epg))
    return objs[0].tDn


def get_AppD(application):
    """
    This function is to return the tier flow context of the application analyzed by AppDynamics
    """
    if not application:
        appdict = readfile("app_mapping.json")
    else:
        appdict = get_appdict(application)
    return appdict


def get_Relationships(application):
    """
    This function is to return the relationships between uEPGs
    """
    if not application:
        relation = readfile("tier_relationship.json")
    else:
        # TODO: call AppD for NetViz information
        relation = {"coursefront": {"app2web": ["consume"]}, "coursefund": {"app2web": ["provide"]}}
    return relation


def micro_segmentation(tenant_name, aprofile_name, epg_name, app_name):
    """
    This function micro-segments existing EPG into uEPGs based on AppDynamics analysis.
    """

    # test if the manual inputs exist
    test_input(tenant_name, aprofile_name, epg_name)

    # get variables we need
    bd_name = get_BDname(tenant_name, aprofile_name, epg_name)
    vmm_dn = get_VMM(tenant_name, aprofile_name, epg_name)
    app_mapping = get_AppD(app_name)
    epg_relationship = get_Relationships(app_name)

    # the top level object on which operations will be made
    polUni = cobra.model.pol.Uni('')
    fvTenant = cobra.model.fv.Tenant(polUni, tenant_name)

    # Re-config existing Application Profile
    fvAp = cobra.model.fv.Ap(fvTenant, descr='This application has been micro-segmented by microseg_gui',
                             name=aprofile_name,
                             nameAlias='')

    # Re-config existing Base EPG
    fvAEPg_Base = cobra.model.fv.AEPg(fvAp,
                                      descr="The base EPG has been micro-segmented by microseg_gui at " + time.strftime(
                                          "%Y-%m-%d %H:%M:%S", time.localtime()), name=epg_name, pcEnfPref='unenforced',
                                      prefGrMemb='exclude',
                                      shutdown='no')
    if vmm_dn:
        fvRsDomAtt_Base = cobra.model.fv.RsDomAtt(fvAEPg_Base, annotation='', bindingType='none', classPref='useg',
                                                  customEpgName='',
                                                  delimiter='', encap='unknown', encapMode='auto', epgCos='Cos0',
                                                  epgCosPref='disabled', instrImedcy='immediate', lagPolicyName='',
                                                  netflowDir='both', netflowPref='disabled', numPorts='0',
                                                  portAllocation='none',
                                                  primaryEncap='unknown', primaryEncapInner='unknown',
                                                  resImedcy='immediate',
                                                  secondaryEncapInner='unknown', switchingMode='native',
                                                  tDn=vmm_dn, untagged='no')
        vmmSecP_Base = cobra.model.vmm.SecP(fvRsDomAtt_Base, allowPromiscuous='reject', annotation='', descr='',
                                            forgedTransmits='reject', macChanges='reject', name='', nameAlias='',
                                            ownerKey='',
                                            ownerTag='')
    fvRsBd_Base = cobra.model.fv.RsBd(fvAEPg_Base, annotation='', tnFvBDName=bd_name)

    # Create micro-segment for each app tier
    for tier, ips in app_mapping.items():
        # create uEPG
        fvAEPg = cobra.model.fv.AEPg(fvAp, descr='This is a sub-EPG created by microseg_gui',
                                     exceptionTag='', floodOnEncap='disabled', fwdCtrl='',
                                     hasMcastSource='no', isAttrBasedEPg='yes', matchT='AtleastOne', name=tier,
                                     nameAlias='', pcEnfPref='unenforced', prefGrMemb='exclude', prio='unspecified',
                                     shutdown='no')
        if vmm_dn:
            fvRsDomAtt = cobra.model.fv.RsDomAtt(fvAEPg, annotation='', bindingType='none', classPref='encap',
                                                 customEpgName='',
                                                 delimiter='', encap='unknown', encapMode='auto', epgCos='Cos0',
                                                 epgCosPref='disabled', instrImedcy='immediate', lagPolicyName='',
                                                 netflowDir='both', netflowPref='disabled', numPorts='0',
                                                 portAllocation='none',
                                                 primaryEncap='unknown', primaryEncapInner='unknown',
                                                 resImedcy='immediate',
                                                 secondaryEncapInner='unknown', switchingMode='native',
                                                 tDn=vmm_dn, untagged='no')
        fvRsCustQosPol = cobra.model.fv.RsCustQosPol(fvAEPg, annotation='', tnQosCustomPolName='')
        fvRsBd = cobra.model.fv.RsBd(fvAEPg, annotation='', tnFvBDName=bd_name)

        # attribute
        fvCrtrn = cobra.model.fv.Crtrn(fvAEPg, annotation='', descr='', match='any', name='default', nameAlias='',
                                       ownerKey='',
                                       ownerTag='', prec='0')
        nameid = 0
        for ip in ips:
            fvIpAttr = cobra.model.fv.IpAttr(fvCrtrn, annotation='', descr='', ip=ip, name=str(nameid), nameAlias='',
                                             ownerKey='', ownerTag='', usefvSubnet='no')
            nameid += 1

        # build the relationships between uEPGs
        for ctr in epg_relationship[fvAEPg.name].items():
            if "consume" in ctr[1]:
                fvRsCons = cobra.model.fv.RsCons(fvAEPg, annotation='', intent='install', prio='unspecified',
                                                 tnVzBrCPName=ctr[0])
            if "provide" in ctr[1]:
                fvRsProv = cobra.model.fv.RsProv(fvAEPg, annotation='', intent='install', matchT='AtleastOne',
                                                 prio='unspecified', tnVzBrCPName=ctr[0])

    # commit the generated code to APIC
    c = cobra.mit.request.ConfigRequest()
    c.addMo(fvTenant)
    md.commit(c)


def main():
    """
    This main function presents the main window for you to input data and trigger micro-segmentation.
    """

    def do_ok():
        """
        This function triggered when click OK button, begin to micro-segment
        """
        micro_segmentation(cbl_t.get(), cbl_p.get(), cbl_e.get(), en_a.get())
        tk.messagebox.showinfo('Congratulations!',
                               "We have successfully micro-segmented your EPG {} into sub-EPGs!".format(cbl_e.get()))
        exit(0)

    def do_cancel():
        """
        doing cancel
        """
        exit(0)

    def set_ap_list(event):
        """
        This function is to build query for existing ap under the tenant you selected
        """
        cbl_p["values"] = get_ap_list(cbl_t.get())
        cbl_p.current(0)
        cbl_e["values"] = [""]
        cbl_e.current(0)

    def set_epg_list(event):
        """
        This function is to build query for existing EPG under the tenant and AP you selected
        """
        cbl_e["values"] = get_epg_list(cbl_t.get(), cbl_p.get())
        cbl_e.current(0)

    # main function begins
    tenant_list = get_tenant_list()

    # window is the obj name
    window = tk.Tk()
    window.title('Micro-Segmentation for ACI v0.3 by Wei Hang')
    window.geometry('510x340')

    # Lables
    lb_t = tk.Label(window, width=20, font=("Arial", 10), anchor='e', text="Tenant:")
    lb_t.place(x=32, y=50, anchor='nw')

    lb_p = tk.Label(window, width=20, font=("Arial", 10), anchor='e', text="Application Profile:")
    lb_p.place(x=32, y=100, anchor='nw')

    lb_e = tk.Label(window, width=20, font=("Arial", 10), anchor='e', text="Application EPG:")
    lb_e.place(x=32, y=150, anchor='nw')

    lb_a = tk.Label(window, width=20, font=("Arial", 10), anchor='e', text="Application Name:")
    lb_a.place(x=32, y=200, anchor='nw')

    lb_st = tk.Label(window, width=2, fg='red', text="*")
    lb_st.place(x=200, y=50, anchor='nw')

    lb_sp = tk.Label(window, width=2, fg='red', text="*")
    lb_sp.place(x=200, y=100, anchor='nw')

    lb_se = tk.Label(window, width=2, fg='red', text="*")
    lb_se.place(x=200, y=150, anchor='nw')

    # Combo Box Lists
    cbl_t = ttk.Combobox(window, font=("Arial", 10), width=25)
    cbl_t["values"] = tenant_list
    cbl_t.current(0)
    cbl_t.bind("<<ComboboxSelected>>", set_ap_list)
    cbl_t.place(x=220, y=50, anchor='nw')

    cbl_p = ttk.Combobox(window, font=("Arial", 10), width=25)
    cbl_p["values"] = [""]
    cbl_p.current(0)
    cbl_p.bind("<<ComboboxSelected>>", set_epg_list)
    cbl_p.place(x=220, y=100, anchor='nw')

    cbl_e = ttk.Combobox(window, font=("Arial", 10), width=25)
    cbl_e["values"] = [""]
    cbl_e.current(0)
    cbl_e.place(x=220, y=150, anchor='nw')

    # Entry
    en_a = tk.Entry(window, width=28, font=("Arial", 10), show=None)
    en_a.place(x=220, y=200, anchor='nw')

    # Buttons
    bt_ok = tk.Button(window, text='OK', width=15, height=2, font=("Arial", 10), command=do_ok)
    bt_ok.place(x=80, y=265, anchor='nw')

    bt_cancel = tk.Button(window, text='Cancel', width=15, height=2, font=("Arial", 10), command=do_cancel)
    bt_cancel.place(x=300, y=265, anchor='nw')

    # Window's mainloop
    window.mainloop()


if __name__ == '__main__':
    main()
