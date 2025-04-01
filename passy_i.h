#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>

#include <gui/modules/submenu.h>
#include <gui/modules/popup.h>
#include <gui/modules/loading.h>
#include <gui/modules/text_input.h>
#include <gui/modules/number_input.h>
#include <gui/modules/text_box.h>
#include <gui/modules/widget.h>

#include <input/input.h>
#include <lib/flipper_format/flipper_format.h>

#include <lib/nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_device.h>

/* generated by fbt from .png files in images folder */
#include <passy_icons.h>

#include "passy.h"
#include "passy_common.h"
#include "scenes/passy_scene.h"

#define PASSY_TEXT_STORE_SIZE            128
#define PASSY_FILE_NAME_MAX_LENGTH       32
#define PASSY_PASSPORT_NUMBER_MAX_LENGTH 32
#define PASSY_DOB_MAX_LENGTH             8
#define PASSY_DOE_MAX_LENGTH             8

#define PASSY_DG1_MAX_LENGTH 256

enum PassyCustomEvent {
    // Reserve first 100 events for button types and indexes, starting from 0
    PassyCustomEventReserved = 100,

    PassyCustomEventViewExit,
    PassyCustomEventTextInputDone,
    PassyCustomEventNumberInputDone,
    // Read card events
    PassyCustomEventReaderError,
    PassyCustomEventReaderSuccess,
    PassyCustomEventReaderDetected,
    PassyCustomEventReaderAuthenticated,
    PassyCustomEventReaderReading,
};

struct Passy {
    ViewDispatcher* view_dispatcher;
    Gui* gui;
    NotificationApp* notifications;
    SceneManager* scene_manager;
    Storage* storage;

    char text_store[PASSY_TEXT_STORE_SIZE + 1];
    FuriString* text_box_store;

    // Common Views
    Submenu* submenu;
    Popup* popup;
    Loading* loading;
    TextInput* text_input;
    NumberInput* number_input;
    TextBox* text_box;
    Widget* widget;
    DialogsApp* dialogs;

    Nfc* nfc;
    NfcListener* listener;
    NfcPoller* poller;
    NfcDevice* nfc_device;

    FuriString* load_path;
    char file_name[PASSY_FILE_NAME_MAX_LENGTH + 1];

    char passport_number[PASSY_PASSPORT_NUMBER_MAX_LENGTH + 1];
    char date_of_birth[PASSY_DOB_MAX_LENGTH + 1];
    char date_of_expiry[PASSY_DOE_MAX_LENGTH + 1];

    BitBuffer* DG1;

    PassyReadType read_type;
};

typedef enum {
    PassyViewMenu,
    PassyViewPopup,
    PassyViewLoading,
    PassyViewTextInput,
    PassyViewNumberInput,
    PassyViewTextBox,
    PassyViewWidget,
} PassyView;

void passy_text_store_set(Passy* passy, const char* text, ...);

void passy_text_store_clear(Passy* passy);

void passy_blink_start(Passy* passy);

void passy_blink_stop(Passy* passy);

void passy_show_loading_popup(void* context, bool show);
