'''gor@automation-oVirt-Node:~/robocop/suites/system/rtp/walmart_bna/Walmart_Pytest$ cat test_UdpRollcage.py'''
from lib.uiAutomation.platformCommon import platformCommon
import pytest
from configparser import ConfigParser
from lib.logger import Logger
from lib.uiAutomation.SRPlatform import SRPlatform
from lib.uiAutomation.SRButler import SRButler
from lib.platformFunctions import PlatformFunctions
from lib.pgsqlHelper import pgsqlHelper
from lib.butlerFunctions import ButlerFunctions
from lib.graphqlFunctions import GraphqlFunctions
from lib.apiHelper import apiHelper
from lib.butlerserver import butlerserver
from lib.baseFunctions import baseFunctions
import json
import time

platform = platformCommon()
platform_func = PlatformFunctions()
config = ConfigParser()
logger = Logger.__call__().get_logger()
sr_platform = SRPlatform()
sr_butler = SRButler()
pgsql = pgsqlHelper()
graphql = GraphqlFunctions()
butler = ButlerFunctions()
api_helper = apiHelper()
butler_server = butlerserver()
base = baseFunctions()

"""
Test Cases for GM-61049
Config file to refer : conf/scrum_features.cfg
How to Execute : python3 -m pytest suites/Solution/Walmart_Pytest/test_UdpRollcage.py -v -s --junitxml="result_ttp.xml" --log-file=pytest_ttp.log --config_file="walmart_canada.cfg" --html=pytest_report.html --capture sys
"""


@pytest.fixture(scope="class")
def setup_teardown(request, config_file):
    # Arrange
    logger.info("Arrange/Setup -  Common for all the TCs")
    config.read(config_file)
    request.cls.plat_host = config['platform']['host']
    request.cls.butler_host = config['butler']['host']
    request.cls.user_name = config['butler']['username']
    request.cls.user_gor = config['butler']['user2']
    request.cls.password = config['butler']['password']
    request.cls.pps_back_side = config['put']['back_side']
    request.cls.pps_front_side = config['put']['front_side']
    request.cls.pps_id = config['put']['udp_roll_cage_pps_id']
    request.cls.filename = config['masterdata']['filename']
    request.cls.sheetname = config['masterdata']['sheetname']
    request.cls.valid_sku = config['put']['valid_sku_udprc1']
    request.cls.valid_sku1 = config['put']['valid_sku_udprc2']
    yield
    # Cleanup
    logger.info("Cleanup completed -  Common for all the TCs")


@pytest.mark.usefixtures("setup_teardown")
class TestUDPRollCageFlows:

    def test_single_roll_cage_docked_happy_flow_walmart(self):
        self.tc_summary = "Verify happy flow for udp staging"
        # Act
        logger.info("Act")

        # Clean the system
        butler_server.clean_dockstation_pps(self.butler_host, self.pps_id, [2401, 2402, 2403, 2404], self.user_name,
                                            self.password)
        logger.info("Cleanup completed")

        # Set configs
        butler_server.setEnviromentVariable(self.butler_host, "pps_config",
                                            "#{38 => [{ud_put_enabled, true}, {put_roll_cage_required, true}]}")
        butler_server.restart_pps([self.pps_id], self.butler_host, plathost=self.plat_host)

        # Create Item
        platform_func.createItem(self.plat_host, self.filename, self.sheetname, "24")

        # Create Tote
        tote_barcode = "tote_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode,
            skuDict={self.valid_sku: 5},
            tote=True,
            container=False,
            serialised=False, uri=False, toteId=True)
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id = response['id']
        logger.info(f"tote id: {tote_id}")
        logger.info(f"tote barcode: {tote_barcode}")

        # Create Container
        container_barcode = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode, self.valid_sku, 4, "Item", 4)
        container_id = response['id']
        logger.info(f"container id: {container_id}")
        logger.info(f"container barcode: {container_barcode}")

        # Create Roll Cage
        roll_cage_barcode = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        coordinates = [[0, 0], [61, 0], [0, 99], [0, 33], [61, 99], [0, 66], [61, 66], [61, 132], [61, 33], [0, 132]]
        sr_ids = [tote_id, container_id]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode, coordinates, sr_ids, "put_1",
                                         self.user_name, self.password)
        logger.info(f"roll cage id: {roll_cage_barcode}")

        # Login on front screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Scan Roll cage, this is check that wrong barcode scan and resource locks are released
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)

        # Login on back screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_back_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Dock Roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        #################################################################

        # Check front seat login
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on front screen.")
            assert login
        else:
            logger.info("Logged in.")

        #################################################################

        # Check wait for msu screen
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # Wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # Check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and len(docked_dict) == 1 and docked_dict == {"1": "left"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # Check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # Check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan Invalid Roll Cage bin barcode - Roll Cage bin barcode does not exist
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode + "_999",
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # Check notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host,
                                                                                      self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side,
                                                                                      dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan Invalid Roll Cage bin barcode - Roll Cage bin does not contain any SrId
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode + "_05", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # Check for notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side, dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Rollcage bin is empty":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        ##################################################################

        # Scan valid Roll Cage bin barcode where it contains tote srid
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode + "_01", self.pps_id,
                            self.pps_front_side, skip_checks=True)
        # Check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # Check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # Check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # Check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "5":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan valid Roll Cage bin barcode where it contains container srid
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode + "_02", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # Check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "2":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # Check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        expected_notification = "Switched to Bin"
        if get_notification_valid_roll_cage_bin != expected_notification:
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # Check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # Check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan valid pps bin PPTL barcode where it contains tote srid
        base.processBarcode(self.butler_host, self.user_name, self.password, "F38_01", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        expected_notification = "Switched to Bin"
        if get_notification_valid_roll_cage_bin != expected_notification:
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "5":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan invalid SKU in waiting for entity scan
        base.processBarcode(self.butler_host, self.user_name, self.password, "qwerty", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Scan Entity or Scan Bin Header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host,
                                                       ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin header unsuccessful. TC failed!")
            assert header_wait_for_entity_scan

        # check notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host,
                                                                                      self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side,
                                                                                      dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "5":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Update KQ to 2 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=2, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 2:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        #################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan Entity or Scan Bin to confirm header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_slot = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                     self.password, self.plat_host,
                                                                     self.pps_id,
                                                                     self.pps_front_side, dual=False)
        if get_notification_scan_slot != "Slot scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan Container barcode in wait for entity scan
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm header unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "2":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                           self.password, self.plat_host,
                                                           self.pps_id, self.pps_front_side, dual=False)
        if get_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Cancel Scan in wait for slot scan screen
        butler.cancelToteScan(self.butler_host, self.user_name, self.password, self.pps_id,
                              self.pps_front_side, dual=False, plathost=self.plat_host, opr_delay=True,
                              tote_barcode=False)
        # check Scan Entity or Scan Bin header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host,
                                                       ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id,
                                                       self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin header unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "2":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                           self.password, self.plat_host,
                                                           self.pps_id, self.pps_front_side, dual=False)
        if get_notification != "Cancel scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan Container barcode in wait for entity scan
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host,
                                                     ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id,
                                                     self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm header unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "2":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                           self.password, self.plat_host,
                                                           self.pps_id, self.pps_front_side, dual=False)
        if get_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan Invalid Slot Barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, "99999999.0.A.01",
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm header unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check notification
        get_notification_invalid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                             self.user_name, self.password,
                                                                             self.plat_host, self.pps_id,
                                                                             self.pps_front_side, dual=False)
        if get_notification_invalid_slot_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        ################################################################

        # Scan valid slot barcode in wait for slot scan screen
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[1]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and len(docked_dict) == 1 and docked_dict == {"1": "left"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # check notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "2":
            logger.info("Bin number closed doesn't match")
            assert False

        #################################################################

        # Scan Container barcode which has already been processed
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side, dual=False)
        if get_notification_invalid_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan Roll Cage bin barcode whose Container has already been processed
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode + "_02",
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if get_notification_invalid_scan != "Rollcage bin is empty":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                          plathost=self.plat_host)

        #################################################################

        # Scan PPTL barcode whose Container has already been processed
        base.processBarcode(self.butler_host, self.user_name, self.password, "F38_02", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if get_notification_invalid_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        #### Change for tote barcode
        # Scan valid Rollcage bin barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Press Send MSU button
        base.process_pps_event(self.butler_host, self.user_name, self.password, 'send_msu', '',
                               self.pps_id, self.pps_front_side, dual=False, udp_send_msu=True,
                               plathost=self.plat_host)
        ##### Change the header
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        #################################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Update KQ to 2 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=2, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side,
                                         plathost=self.plat_host)
        if current_kq == 2:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        #################################################################

        # Update KQ to 1 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=1, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side,
                                         plathost=self.plat_host)
        if current_kq == 1:
            logger.info("Decrease KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert current_kq

        #################################################################

        # Update KQ to 3 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=3, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side,
                                         plathost=self.plat_host)
        if current_kq == 3:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert current_kq

        #################################################################

        # Scan valid slot barcode in wait for slot scan screen
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # scan roll cage to undock header
        header_scan_roll_cage_to_undock = base.checkHeader(self.butler_host,
                                                           ["Scan roll cage to Undock"],
                                                           self.user_name, self.password, self.pps_id,
                                                           self.pps_front_side,
                                                           dual=False, plathost=self.plat_host)
        if header_scan_roll_cage_to_undock:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_scan_roll_cage_to_undock

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if ready_for_undock_dict and len(ready_for_undock_dict) == 1 and ready_for_undock_dict == {"1": "left"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # check notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "1":
            logger.info("Bin number closed doesn't match. TC Failed!")
            assert False

        #################################################################

        # Scan Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # system idle header
        header_system_idle = base.checkHeader(self.butler_host, ["System is Idle"], self.user_name,
                                              self.password, self.pps_id, self.pps_front_side,
                                              dual=False, plathost=self.plat_host)
        if header_system_idle:
            logger.info("System is Idle header")
        else:
            logger.info("System is Idle header unsuccessful. TC failed!")
            assert header_system_idle

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and len(undocked_dict) == 1 and undocked_dict == {"1": "left"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Press pptl from back seat to undock roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        time.sleep(2)

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ####################################################
        # Clear the inventory
        inventory_clear = butler_server.delete_inventory_by_esr(self.butler_host, [tote_barcode, container_barcode],
                                                                self.user_name, self.password)
        if inventory_clear:
            logger.info("Inventory Cleared. TC Passed!")
        else:
            logger.info("Unable to clear inventory. TC failed!")
            assert inventory_clear

    def test_multiple_roll_cage_docked_happy_flow_walmart(self):
        self.tc_summary = "Verify happy flow for udp rollcage flow with multiple rollcages docked"
        # Act
        logger.info("Act")

        # Cleanup the system
        butler_server.clean_dockstation_pps(self.butler_host, self.pps_id, [2401, 2402, 2403, 2404], self.user_name,
                                            self.password)
        logger.info("Cleanup completed")

        # Create Item
        platform_func.createItem(self.plat_host, self.filename, self.sheetname, "24")
        platform_func.createItem(self.plat_host, self.filename, self.sheetname, "25")

        # Create Tote 1
        tote_barcode1 = "tote_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id_1 = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode1,
            skuDict={self.valid_sku: 3, self.valid_sku1: 4},
            tote=True,
            container=False,
            serialised=False, uri=False, toteId=True)
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id1 = response['id']

        logger.info(f"tote_barcode1: {tote_barcode1}")

        # Create Roll Cage 1
        roll_cage_barcode1 = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        coordinates = [[0, 0], [61, 0], [0, 99], [0, 33], [61, 99], [0, 66], [61, 66], [61, 132], [61, 33], [0, 132]]
        sr_ids = [tote_id1]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode1, coordinates, sr_ids, "put_1",
                                         self.user_name,
                                         self.password)
        logger.info(f"roll_cage_barcode1: {roll_cage_barcode1}")

        # login on back screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_back_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Dock Roll cage 1
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode1,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        logger.info(f"scan: {scan}")
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage 1 barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        logger.info(f"pptl scan: {scan}")
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode for roll cage 1")
            assert scan

        # Create container 2
        container_barcode2 = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode2, self.valid_sku, 4, "Item", 4)
        container_id2 = response['id']
        logger.info(f"container_barcode2: {container_barcode2}")

        # Create Roll Cage 2
        roll_cage_barcode2 = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        sr_ids = [container_id2]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode2, coordinates, sr_ids, "put_1",
                                         self.user_name,
                                         self.password)
        logger.info(f"roll_cage_barcode2: {roll_cage_barcode2}")

        # Dock Roll cage 2
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode2,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage 2 barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_13",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode for roll cage 2")
            assert scan

        # Create Tote 3
        tote_barcode3 = "tote_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id3 = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode3,
            skuDict={self.valid_sku: 4, self.valid_sku1: 3},
            tote=True,
            container=False,
            serialised=False, uri=False, toteId=True)
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id3 = response['id']
        logger.info(f"tote_barcode3: {tote_barcode3}")

        # Create container 3
        container_barcode3 = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode3, self.valid_sku1, 2, "Item",
                                                       2)
        container_id3 = response['id']
        logger.info(f"container_barcode3: {container_barcode3}")

        # Create Roll Cage 3
        roll_cage_barcode3 = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        sr_ids = [tote_id3, container_id3]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode3, coordinates, sr_ids, "put_1",
                                         self.user_name,
                                         self.password)
        logger.info(f"roll_cage_barcode3: {roll_cage_barcode3}")

        # Dock Roll cage 3
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode3,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage 3 barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_28",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode for roll cage 3")
            assert scan

        #################################################################

        # check front seat login
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on front screen.")
            assert login
        else:
            logger.info("Logged in.")

        #################################################################

        # check wait for msu screen
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        ### Change the header
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '2': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan Invalid Roll Cage bin barcode - Roll Cage bin barcode does not exist
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode2 + "_999",
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host,
                                                                                      self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side,
                                                                                      dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan Invalid Roll Cage bin barcode - Roll Cage bin does not contain any SrId
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode1 + "_05", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side, dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Rollcage bin is empty":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan valid container present inside roll cage 2
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode2, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "11":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)

        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"2": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan roll cage to Undock header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan roll cage to Undock"], self.user_name,
                                                       self.password, self.pps_id, self.pps_front_side, dual=False,
                                                       plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan roll cage to Undock")
        else:
            logger.info("Scan roll cage to Undock unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check Bin close successfully notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "11":
            logger.info("Bin number closed doesn't match")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {'2': 'left'}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan Roll Cage 1 barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode1,
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Scan roll cage to Undock header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan roll cage to Undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_roll_cage_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                  self.password, self.plat_host,
                                                                                  self.pps_id, self.pps_front_side,
                                                                                  dual=False)
        if get_notification_invalid_roll_cage_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {'2': 'left'}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan Tote Barcode from Roll Cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode3,
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Scan roll cage to Undock header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan roll cage to Undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_roll_cage_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                  self.password, self.plat_host,
                                                                                  self.pps_id, self.pps_front_side,
                                                                                  dual=False)
        if get_notification_invalid_roll_cage_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {'2': 'left'}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan Container Barcode from Roll Cage 2
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode2,
                            self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # Scan roll cage to Undock header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan roll cage to Undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_roll_cage_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                  self.password, self.plat_host,
                                                                                  self.pps_id, self.pps_front_side,
                                                                                  dual=False)
        if get_notification_invalid_roll_cage_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {'2': 'left'}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan PPTL Barcode corresponding to the roll cage bin where container from roll cage 2 has stored
        base.processBarcode(self.butler_host, self.user_name, self.password, "F38_13",
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # Scan roll cage to Undock header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan roll cage to Undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        get_notification_invalid_roll_cage_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                  self.password, self.plat_host,
                                                                                  self.pps_id, self.pps_front_side,
                                                                                  dual=False)
        if get_notification_invalid_roll_cage_scan != "Wrong barcode scanned":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {'2': 'left'}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan roll cage 2 barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode2,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # Scan Bin from a roll cage or scan roll cage to undock header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {'1': 'left', '3': 'right'}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {'2': 'left'}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan valid tote barcode from roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode3,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan valid tote barcode from roll cage 1
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode1,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan roll cage bin barcode where a container is present in roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode3 + "_02",
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "22":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan PPTL of roll cage bin barcode where a tote is present of roll cage 1
        base.processBarcode(self.butler_host, self.user_name, self.password, "F38_01",
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan roll cage bin barcode without srid from roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode3 + "_08", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check for notification
        get_notification_invalid_roll_cage_bin_scan = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                                      self.password, self.plat_host,
                                                                                      self.pps_id,
                                                                                      self.pps_front_side, dual=False)
        if get_notification_invalid_roll_cage_bin_scan != "Rollcage bin is empty":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        base.clearUIPopUp(self.butler_host, self.user_name, self.password, self.pps_id,
                          self.pps_front_side, plathost=self.plat_host)

        #################################################################

        # Scan roll cage bin barcode where a container is present of roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode3 + "_02",
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "22":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ###############################################################

        # Scan valid container present inside roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode3, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "22":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "1":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ##############################################################

        # Scan valid slot barcode in wait for slot scan screen
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[1]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {"1": "left", "3": "right"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {'2': 'left'}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # check notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                          self.user_name, self.password,
                                                                          self.plat_host, self.pps_id,
                                                                          self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "22":
            logger.info("Bin number closed doesn't match")
            assert False

        ################################################################

        # Scan tote barcode present in roll cage 1
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode1,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Update KQ to 3 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=3, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 3:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        ################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan Entity or Scan Bin to confirm header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_slot = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                     self.password, self.plat_host,
                                                                     self.pps_id,
                                                                     self.pps_front_side, dual=False)
        if get_notification_scan_slot != "Slot scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "4":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan tote barcode present in roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode3,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "7":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Update KQ to 4 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=4, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 4:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        ################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan Entity or Scan Bin to confirm header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"], self.user_name,
                                                       self.password, self.pps_id, self.pps_front_side, dual=False,
                                                       plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_slot = base.getNotificationDescription(self.butler_host, self.user_name, self.password,
                                                                     self.plat_host, self.pps_id, self.pps_front_side,
                                                                     dual=False)
        if get_notification_scan_slot != "Slot scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan tote barcode present in roll cage 1
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode1,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "4":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku1, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "4":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ################################################################

        # Update KQ to 4 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=4, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 4:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        ################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan roll cage to Undock header
        header_wait_for_roll_cage_undock_scan = base.checkHeader(self.butler_host, ["Scan roll cage to Undock"],
                                                                 self.user_name, self.password, self.pps_id,
                                                                 self.pps_front_side,
                                                                 dual=False, plathost=self.plat_host)
        if header_wait_for_roll_cage_undock_scan:
            logger.info("Scan roll cage to Undock")
        else:
            logger.info("Scan roll cage to Undock unsuccessful. TC Failed!")
            assert header_wait_for_roll_cage_undock_scan

        # check notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "1":
            logger.info("Bin number closed doesn't match")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {"3": "right"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {'2': 'left'}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {"1": "left"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan valid Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode1, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and docked_dict == {"3": "right"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {'1': 'left', '2': 'left'}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan tote barcode present in roll cage 3
        base.processBarcode(self.butler_host, self.user_name, self.password, tote_barcode3,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        if get_notification_valid_roll_cage_bin != "Switched to Bin":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        ###############################################################

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku1, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"3": "right"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Update KQ to 3 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=3, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 3:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        ################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan roll cage to Undock header
        header_wait_for_roll_cage_undock_scan = base.checkHeader(self.butler_host, ["Scan roll cage to Undock"],
                                                                 self.user_name, self.password, self.pps_id,
                                                                 self.pps_front_side,
                                                                 dual=False, plathost=self.plat_host)
        if header_wait_for_roll_cage_undock_scan:
            logger.info("Scan roll cage to Undock")
        else:
            logger.info("Scan roll cage to Undock unsuccessful. TC Failed!")
            assert header_wait_for_roll_cage_undock_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "21":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_slot_scan = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_valid_slot_scan != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check bin number
        get_bin_number = base.get_bin(self.butler_host, self.user_name, self.password, self.plat_host, self.pps_id,
                                      self.pps_front_side, dual=False)
        if get_bin_number != "21":
            logger.info("Bin number closed doesn't match")
            assert False

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {'1': 'left', '2': 'left'}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {"3": "right"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ################################################################

        # Press pptl from back seat to undock roll cage2
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_13",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)

        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {"1": "left"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if ready_for_undock_dict and ready_for_undock_dict == {"3": "right"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ################################################################

        # Scan valid Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode3, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # system idle header
        header_system_idle = base.checkHeader(self.butler_host, ["System is Idle"], self.user_name,
                                              self.password, self.pps_id, self.pps_front_side,
                                              dual=False, plathost=self.plat_host)
        if header_system_idle:
            logger.info("System is Idle header")
        else:
            logger.info("System is Idle header unsuccessful. TC failed!")
            assert header_system_idle

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {"1": "left", "3": "right"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if ready_for_undock_dict:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # Press pptl from back seat to undock roll cage1
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)

        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and undocked_dict == {"3": "right"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # Press pptl from back seat to undock roll cage3
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_28",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)

        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ####################################################
        # Clear the inventory
        inventory_clear = butler_server.delete_inventory_by_esr(self.butler_host,
                                                       [tote_barcode1, container_barcode2, tote_barcode3, container_barcode3],
                                                       self.user_name, self.password)
        if inventory_clear:
            logger.info("Inventory Cleared. TC Passed!")
        else:
            logger.info("Unable to clear inventory. TC failed!")
            assert inventory_clear

    def test_missing_rollcage_exception_from_waiting_for_bin_scan_state(self):
        self.tc_summary = "Verify rollcage missing exception for UD Rollcage Flow"
        # Act
        logger.info("Act")

        # Cleanup the system
        butler_server.clean_dockstation_pps(self.butler_host, self.pps_id, [2401, 2402, 2403, 2404], self.user_name,
                                            self.password)
        logger.info("Cleanup completed")

        # Set configs
        butler_server.setEnviromentVariable(self.butler_host, "pps_config",
                                            "#{38 => [{ud_put_enabled, true}, {put_roll_cage_required, true}]}")
        butler_server.restart_pps([self.pps_id], self.butler_host, plathost=self.plat_host)

        # Create Item
        platform_func.createItem(self.plat_host, self.filename, self.sheetname, "24")

        # Create Tote
        tote_barcode = time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode,
            skuDict={self.valid_sku: 5},
            tote=True,
            container=False,
            serialised=False, uri=False, toteId=True)
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id = response['id']
        logger.info(f"tote id: {tote_id}")
        logger.info(f"tote barcode: {tote_barcode}")

        # Create Container
        container_barcode = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode, self.valid_sku, 4, "Item", 4)
        container_id = response['id']
        logger.info(f"container id: {container_id}")
        logger.info(f"container barcode: {container_barcode}")

        # Create Roll Cage
        roll_cage_barcode = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        coordinates = [[0, 0], [61, 0], [0, 99], [0, 33], [61, 99], [0, 66], [61, 66], [61, 132], [61, 33], [0, 132]]
        sr_ids = [tote_id, container_id]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode, coordinates, sr_ids, "put_1",
                                         self.user_name, self.password)
        logger.info(f"roll cage id: {roll_cage_barcode}")

        # login on back screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_back_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Dock Roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        #################################################################

        # check front seat login
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on front screen.")
            assert login
        else:
            logger.info("Logged in.")

        #################################################################

         # check wait for msu screen
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        ### Change the header
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and len(docked_dict) == 1 and docked_dict == {"1": "left"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name, self.password, dual=False,
                                                               plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################
        time.sleep(5)
        # Scan Roll Cage barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        missing_rollcage_id = base.get_missing_exception_rollcage_id(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if missing_rollcage_id != roll_cage_barcode:
            logger.info(f"Expected: {roll_cage_barcode}, Received: {missing_rollcage_id}. TC Failed!")
            assert False

        ################################################################

        # Confirm Exception
        base.process_missing_exception_event(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, event_name=True)

        # scan roll cage to undock header
        header_scan_roll_cage_to_undock = base.checkHeader(self.butler_host,
                                                           ["Scan roll cage to Undock"],
                                                           self.user_name, self.password, self.pps_id,
                                                           self.pps_front_side,
                                                           dual=False, plathost=self.plat_host)
        if header_scan_roll_cage_to_undock:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_scan_roll_cage_to_undock

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if ready_for_undock_dict and len(ready_for_undock_dict) == 1 and ready_for_undock_dict == {"1": "left"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # check notification
        get_notification_rollcage_close = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_rollcage_close != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False
        
        missing_modal_cleared = base.get_missing_exception_cleared(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if missing_modal_cleared == False:
            logger.info("Expected: missing modal to be cleared but data found in UI state data")
            assert False

        #################################################################

        # Scan Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # system idle header
        header_system_idle = base.checkHeader(self.butler_host, ["System is Idle"], self.user_name,
                                              self.password, self.pps_id, self.pps_front_side,
                                              dual=False, plathost=self.plat_host)
        if header_system_idle:
            logger.info("System is Idle header")
        else:
            logger.info("System is Idle header unsuccessful. TC failed!")
            assert header_system_idle

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and len(undocked_dict) == 1 and undocked_dict == {"1": "left"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Press pptl from back seat to undock roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ####################################################
        # Clear the inventory
        inventory_clear = butler_server.delete_inventory_by_esr(self.butler_host, [tote_barcode, container_barcode],
                                                                self.user_name, self.password)
        if inventory_clear:
            logger.info("Inventory Cleared. TC Passed!")
        else:
            logger.info("Unable to clear inventory. TC failed!")
            assert inventory_clear

    def test_missing_rollcage_exception_from_waiting_for_entity_scan_state(self):
        self.tc_summary = "Verify rollcage missing exception for UD Rollcage Flow"
        # Act
        logger.info("Act")

        # Cleanup the system
        butler_server.clean_dockstation_pps(self.butler_host, self.pps_id, [2401, 2402, 2403, 2404], self.user_name,
                                            self.password)
        logger.info("Cleanup completed")

        # Set configs
        butler_server.setEnviromentVariable(self.butler_host, "pps_config",
                                            "#{38 => [{ud_put_enabled, true}, {put_roll_cage_required, true}]}")
        butler_server.restart_pps([self.pps_id], self.butler_host, plathost=self.plat_host)

        # Create Item
        platform_func.createItem(self.plat_host, self.filename, self.sheetname, "26")

        # Create Tote
        tote_barcode = time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode,
            skuDict={self.valid_sku: 5},
            tote=True,
            container=False,
            serialised=False, uri=False, toteId=True)
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id = response['id']
        logger.info(f"tote id: {tote_id}")
        logger.info(f"tote barcode: {tote_barcode}")

        # Create Container
        container_barcode = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode, self.valid_sku, 4, "Item", 4)
        container_id = response['id']
        logger.info(f"container id: {container_id}")
        logger.info(f"container barcode: {container_barcode}")

        # Create Roll Cage
        roll_cage_barcode = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        coordinates = [[0, 0], [61, 0], [0, 99], [0, 33], [61, 99], [0, 66], [61, 66], [61, 132], [61, 33], [0, 132]]
        sr_ids = [tote_id, container_id]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode, coordinates, sr_ids, "put_1",
                                         self.user_name,
                                         self.password)
        logger.info(f"roll cage id: {roll_cage_barcode}")

        # login on back screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_back_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Dock Roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode for roll cage 1")
            assert scan

        #################################################################

        # check front seat login
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on front screen.")
            assert login
        else:
            logger.info("Logged in.")

        #################################################################

        # check wait for msu screen
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        ### Change the header
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if docked_dict and len(docked_dict) == 1 and docked_dict == {"1": "left"}:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Scan valid pps bin PPTL barcode where it contains tote srid
        base.processBarcode(self.butler_host, self.user_name, self.password, "F38_01", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        expected_notification = "Switched to Bin"
        if get_notification_valid_roll_cage_bin != expected_notification:
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "5":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False
        
        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current active dock station
        current_active_dock_station_dict = base.get_current_active_dock_station_dict(self.butler_host, self.pps_id,
                                                                                     self.pps_front_side,
                                                                                     self.user_name, self.password,
                                                                                     dual=False,
                                                                                     plathost=self.plat_host)
        if current_active_dock_station_dict and len(current_active_dock_station_dict) == 1 and \
                current_active_dock_station_dict == {"1": "left"}:
            logger.info("current active dock station")
        else:
            logger.info("current active dock station unsuccessful. TC failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "5":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False

        #################################################################

        # Update KQ to 2 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=2, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check notification
        get_kq_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                              self.password, self.plat_host,
                                                              self.pps_id, self.pps_front_side,
                                                              dual=False)
        if get_kq_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side, plathost=self.plat_host)
        if current_kq == 2:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        #################################################################

        # Scan slot barcode in waiting for slot scan state
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Scan Entity or Scan Bin to confirm header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_slot = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                     self.password, self.plat_host,
                                                                     self.pps_id,
                                                                     self.pps_front_side, dual=False)
        if get_notification_scan_slot != "Slot scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check for current pps bin count
        pps_bin_count = base.getBinCount(self.butler_host, current_bin, self.user_name, self.password,
                                         self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if pps_bin_count == "3":
            logger.info("pps bin count")
        else:
            logger.info("pps bin count unsuccessful. TC failed!")
            assert False
            
        #################################################################
        # Scan Roll Cage barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Entity or Scan Bin"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Entity or Scan Bin header")
        else:
            logger.info("Scan Entity or Scan Bin header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # check notification
        missing_rollcage_id = base.get_missing_exception_rollcage_id(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if missing_rollcage_id != roll_cage_barcode:
            logger.info(f"Expected: {roll_cage_barcode}, Received: {missing_rollcage_id}. TC Failed!")
            assert False

        ################################################################

        # Confirm Exception
        base.process_missing_exception_event(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, event_name=True)

        # scan roll cage to undock header
        header_scan_roll_cage_to_undock = base.checkHeader(self.butler_host,
                                                           ["Scan roll cage to Undock"],
                                                           self.user_name, self.password, self.pps_id,
                                                           self.pps_front_side,
                                                           dual=False, plathost=self.plat_host)
        if header_scan_roll_cage_to_undock:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_scan_roll_cage_to_undock

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if ready_for_undock_dict and len(ready_for_undock_dict) == 1 and ready_for_undock_dict == {"1": "left"}:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        # check notification
        get_notification_rollcage_close = base.getNotificationDescription(self.butler_host,
                                                                           self.user_name, self.password,
                                                                           self.plat_host, self.pps_id,
                                                                           self.pps_front_side, dual=False)
        if get_notification_rollcage_close != "Bin ~p closed succesfully":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        missing_modal_cleared = base.get_missing_exception_cleared(self.butler_host, self.user_name,
                                                                        self.password, self.plat_host,
                                                                        self.pps_id, self.pps_front_side,
                                                                        dual=False)
        if missing_modal_cleared == False:
            logger.info("Expected: missing modal to be cleared but data found in UI state data")
            assert False

        #################################################################

        # Scan Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # system idle header
        header_system_idle = base.checkHeader(self.butler_host, ["System is Idle"], self.user_name,
                                              self.password, self.pps_id, self.pps_front_side,
                                              dual=False, plathost=self.plat_host)
        if header_system_idle:
            logger.info("System is Idle header")
        else:
            logger.info("System is Idle header unsuccessful. TC failed!")
            assert header_system_idle

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if undocked_dict and len(undocked_dict) == 1 and undocked_dict == {"1": "left"}:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        #################################################################

        # Press pptl from back seat to undock roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        # check for docked dictionary
        docked_dict = base.get_docked_dict(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                           self.password, dual=False, plathost=self.plat_host)
        if not docked_dict:
            logger.info("docked")
        else:
            logger.info("docked unsuccessful. TC failed!")
            assert False

        # check for undocked dictionary
        undocked_dict = base.get_undocked_list(self.butler_host, self.pps_id, self.pps_front_side, self.user_name,
                                               self.password, dual=False, plathost=self.plat_host)
        if not undocked_dict:
            logger.info("undocked")
        else:
            logger.info("undocked unsuccessful. TC failed!")
            assert False

        # check for ready_for_undock dictionary
        ready_for_undock_dict = base.get_ready_for_undock_list(self.butler_host, self.pps_id, self.pps_front_side,
                                                               self.user_name,
                                                               self.password, dual=False, plathost=self.plat_host)
        if not ready_for_undock_dict:
            logger.info("ready for undock")
        else:
            logger.info("ready for undock unsuccessful. TC failed!")
            assert False

        ####################################################
        # Clear the inventory
        inventory_clear = butler_server.delete_inventory_by_esr(self.butler_host, [tote_barcode, container_barcode],
                                                                self.user_name, self.password)
        if inventory_clear:
            logger.info("Inventory Cleared. TC Passed!")
        else:
            logger.info("Unable to clear inventory. TC failed!")
            assert inventory_clear

    def test_single_roll_cage_docked_damage_exception(self):
        self.tc_summary = "Verify Damage Exception Flow for UDP Rollcage"
        # Act
        logger.info("Act")

        # Clean the system
        butler_server.clean_dockstation_pps(self.butler_host, self.pps_id, [2401, 2402, 2403, 2404], self.user_name,
                                   self.password)
        logger.info("Cleanup completed")

        # Set configs
        butler_server.setEnviromentVariable(self.butler_host, "pps_config",
                                            "#{38 => [{ud_put_enabled, true}, {put_roll_cage_required, true}]}")
        butler_server.restart_pps([self.pps_id], self.butler_host, plathost=self.plat_host)

        # Create Tote
        tote_barcode = "tote_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        tote_data, tote_id = platform_func.createPutExpectationJson(
            externalServiceReqId=tote_barcode,
            skuDict={self.valid_sku: 5},
            tote=True,
            container=False,
            serialised=False,
            uri=False,
            toteId=True
        )
        tote_json = json.dumps(tote_data)
        response = platform_func.postSRMS(self.plat_host, tote_json, self.user_name, self.password)
        tote_id = response['id']
        logger.info(f"tote id: {tote_id}")
        logger.info(f"tote barcode: {tote_barcode}")

        # Create Container
        container_barcode = "cont_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        response = platform_func.create_container_tote(self.plat_host, container_barcode, self.valid_sku, 4, "Item", 4)
        container_id = response['id']
        logger.info(f"container id: {container_id}")
        logger.info(f"container barcode: {container_barcode}")

        # Create Roll Cage
        roll_cage_barcode = "RollCage_" + time.strftime("%d%m") + str(int(time.time() * 1000))
        coordinates = [[0, 0], [61, 0], [0, 99], [0, 33], [61, 99], [0, 66], [61, 66], [61, 132], [61, 33], [0, 132]]
        sr_ids = [tote_id, container_id]
        platform_func.roll_cage_creation(self.plat_host, roll_cage_barcode, coordinates, sr_ids, "put_1",
                                         self.user_name,
                                         self.password)
        logger.info(f"roll cage id: {roll_cage_barcode}")

        # Login on back screen
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_back_side,
                                dual=False, plathost=self.plat_host)

        if not login:
            logger.info("TC Failed! Failed to login on back screen.")
            assert login
        else:
            logger.info("Logged in.")

        # Dock Roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan roll cage barcode")
            assert scan

        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)
        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        #################################################################

        # check front seat login
        login = butler.loginApi(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                                dual=False, plathost=self.plat_host)
        if not login:
            logger.info("TC Failed! Failed to login on front screen.")
            assert login
        else:
            logger.info("Logged in.")

        #################################################################

        # check wait for msu screen
        msu_wait = base.wait_for_msu(self.butler_host, ["Wait for MSU"], self.user_name, self.password,
                                     self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        ### Change the header
        if not msu_wait:
            logger.info("Wait for MSU test unsuccessful. TC Failed!")
            assert msu_wait

        #################################################################

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # Scan valid pps bin PPTL barcode where it contains tote srid
        base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01", self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification_valid_roll_cage_bin = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                               self.password, self.plat_host,
                                                                               self.pps_id,
                                                                               self.pps_front_side, dual=False)
        expected_notification = "Switched to Bin"
        if get_notification_valid_roll_cage_bin != expected_notification:
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # check header
        header_wait_for_entity_scan = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                                       self.user_name, self.password, self.pps_id,
                                                       self.pps_front_side,
                                                       dual=False, plathost=self.plat_host)
        if header_wait_for_entity_scan:
            logger.info("Scan Entity or Scan Bin")
        else:
            logger.info("Scan Entity or Scan Bin unsuccessful. TC Failed!")
            assert header_wait_for_entity_scan

        # Raise damage Exception for 1 qty of first item
        raise_exception = base.raise_damage_exception_ttp(self.butler_host, self.user_name, self.password, self.pps_id,
                                                          self.pps_front_side, self.valid_sku, self.plat_host)
        if not raise_exception:
            logger.info("Error in raise damage exception! TC Failed")
            assert raise_exception
        else:
            logger.info("Raised damaged exception")

        # check header
        header_first_item = base.checkHeader(self.butler_host, ["Scan Entity or Scan Bin"],
                                             self.user_name, self.password, self.pps_id, self.pps_front_side,
                                             dual=False, plathost=self.plat_host)
        if header_first_item:
            logger.info("Damaged exception raised successfully for first item")
        else:
            logger.info("Damaged exception raise failed for first item. TC Failed!")

        # check notification
        get_notification_first_item = base.getNotificationDescription(self.butler_host, self.user_name, self.password,
                                                                      self.plat_host, self.pps_id, self.pps_front_side,
                                                                      dual=False)
        if get_notification_first_item != "Physically Damaged entity reported.":
            logger.info("Notification doesn't match. TC Failed!")
            assert get_notification_first_item

        # Scan valid SKU inside Tote
        base.processBarcode(self.butler_host, self.user_name, self.password, self.valid_sku, self.pps_id,
                            self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host, ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "1":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check Entity scan successful notification
        get_notification_scan_tote_entity = base.getNotificationDescription(self.butler_host, self.user_name,
                                                                            self.password, self.plat_host,
                                                                            self.pps_id,
                                                                            self.pps_front_side, dual=False)
        if get_notification_scan_tote_entity != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # Update KQ to 2 in slot scan screen
        base.updateKQ(self.butler_host, self.user_name, self.password, self.pps_id, self.pps_front_side,
                      qty=4, dual=False, plathost=self.plat_host)
        time.sleep(2)

        # check current KQ
        current_kq = base.get_current_kq(self.butler_host, self.user_name, self.password, self.pps_id,
                                         self.pps_front_side,
                                         plathost=self.plat_host)
        if current_kq == 4:
            logger.info("Increase KQ successful.")
        else:
            logger.info("KQ doesn't match. TC Failed!")
            assert False

        #################################################################

        # Scan valid slot barcode in wait for slot scan screen
        prefix = base.getPrefix(butler_server.getEnviromentVariable(self.butler_host, "msu_slot_barcode_prefix",
                                                                    self.user_gor, self.password))
        all_slot_barcodes = base.getRackBarcodes(self.butler_host, self.user_name, self.password, self.pps_id,
                                                 self.pps_front_side, dual=False, plathost=self.plat_host)
        base.processBarcode(self.butler_host, self.user_name, self.password, prefix + str(all_slot_barcodes[0]),
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # wait for bin scan screen header
        header_wait_for_bin_scan = base.checkHeader(self.butler_host,
                                                    ["Scan Bin from a roll cage or scan roll cage to undock"],
                                                    self.user_name, self.password, self.pps_id, self.pps_front_side,
                                                    dual=False, plathost=self.plat_host)
        if header_wait_for_bin_scan:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header")
        else:
            logger.info("Scan Bin from a roll cage or scan roll cage to undock header unsuccessful. TC failed!")
            assert header_wait_for_bin_scan

        # Scan Container barcode
        base.processBarcode(self.butler_host, self.user_name, self.password, container_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # check Put Entity in Slot and scan Slot to confirm header
        header_wait_for_slot_scan = base.checkHeader(self.butler_host,
                                                     ["Put Entity in Slot and scan Slot to confirm"],
                                                     self.user_name, self.password, self.pps_id,
                                                     self.pps_front_side,
                                                     dual=False, plathost=self.plat_host)
        if header_wait_for_slot_scan:
            logger.info("Put Entity in Slot and scan Slot to confirm")
        else:
            logger.info("Put Entity in Slot and scan Slot to confirm header unsuccessful. TC Failed!")
            assert header_wait_for_slot_scan

        # check current bin
        current_bin = base.get_current_bin_id(self.butler_host, self.user_name, self.password,
                                              self.pps_id, self.pps_front_side, dual=False, plathost=self.plat_host)
        if current_bin != "2":
            logger.info("Current bin doesn't match. TC Failed!")
            assert False

        # check notification
        get_notification = base.getNotificationDescription(self.butler_host, self.user_name,
                                                           self.password, self.plat_host,
                                                           self.pps_id, self.pps_front_side, dual=False)
        if get_notification != "Entity scan successful":
            logger.info("Notification doesn't match. TC Failed!")
            assert False

        # raise exception for container
        raise_exception = base.raise_damage_exception_ttp(self.butler_host, self.user_name, self.password, self.pps_id,
                                                          self.pps_front_side, container_barcode, self.plat_host)
        if not raise_exception:
            logger.info("Error in raise damage exception! TC Failed")
            assert raise_exception
        else:
            logger.info("Raised damaged exception")


        # scan roll cage to undock header
        header_scan_roll_cage_to_undock = base.checkHeader(self.butler_host,
                                                           ["Scan roll cage to Undock"],
                                                           self.user_name, self.password, self.pps_id,
                                                           self.pps_front_side,
                                                           dual=False, plathost=self.plat_host)
        if header_scan_roll_cage_to_undock:
            logger.info("Scan roll cage to Undock header")
        else:
            logger.info("Scan roll cage to Undock header unsuccessful. TC failed!")
            assert header_scan_roll_cage_to_undock


        #################################################################

        # Scan Roll Cage barcode to undock
        base.processBarcode(self.butler_host, self.user_name, self.password, roll_cage_barcode,
                            self.pps_id, self.pps_front_side, skip_checks=True)

        # system idle header
        header_system_idle = base.checkHeader(self.butler_host, ["System is Idle"], self.user_name,
                                              self.password, self.pps_id, self.pps_front_side,
                                              dual=False, plathost=self.plat_host)
        if header_system_idle:
            logger.info("System is Idle header")
        else:
            logger.info("System is Idle header unsuccessful. TC failed!")
            assert header_system_idle

        # Press pptl from back seat to undock roll cage
        scan = base.processBarcode(self.butler_host, self.user_name, self.password, "B38_01",
                                   self.pps_id, self.pps_back_side, plathost=self.plat_host, skip_checks=True)

        if not scan:
            logger.info("Tc Failed! Unable to scan PPTL barcode")
            assert scan

        ####################################################
        # Clear the inventory
        inventory_clear = butler_server.delete_inventory_by_esr(self.butler_host, [tote_barcode, container_barcode],
                                                       self.user_name, self.password)
        if inventory_clear:
            logger.info("Inventory Cleared. TC Passed!")
        else:
            logger.info("Unable to clear inventory. TC failed!")
            assert inventory_clear
''' gor@automation-oVirt-Node:~/robocop/suites/system/rtp/walmart_bna/Walmart_Pytest$'''
