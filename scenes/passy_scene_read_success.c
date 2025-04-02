#include "../passy_i.h"
#include <dolphin/dolphin.h>
#include <storage/storage.h>
#include <lib/toolbox/stream/stream.h>
#include <lib/toolbox/stream/file_stream.h>

#define ASN_EMIT_DEBUG 0
#include <lib/asn1/DG1.h>

#define TAG "PassySceneReadCardSuccess"
// Thank you proxmark code for your passport parsing

void save_dg1_to_file(void* context, DG1_t* dg1, uint8_t td_variant, const char* name) {
    UNUSED(context);
    FuriString* csv_path = furi_string_alloc();
    furi_string_printf(csv_path, "%s/passport_data.csv", STORAGE_APP_DATA_PATH_PREFIX);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, furi_string_get_cstr(csv_path), FSAM_WRITE, FSOM_OPEN_APPEND)) {
        if(storage_file_size(file) == 0) {
            const char headers[] = "Country,Name,DocNumber,DateOfBirth,Sex,ExpiryDate\n";
            storage_file_write(file, headers, sizeof(headers) - 1);
        }
        char csv_line[256];
        if(td_variant == 3) { // Passport form factor
            char* row_1 = (char*)dg1->mrz.buf + 0;
            char* row_2 = (char*)dg1->mrz.buf + 44;

            snprintf(
                csv_line,
                sizeof(csv_line),
                "%.3s,%s,%.9s,%.6s,%.1s,%.6s\n",
                row_1 + 2,
                name,
                row_2,
                row_2 + 13,
                row_2 + 20,
                row_2 + 21);
        } else if(td_variant == 1) { // ID form factor
            char* row_1 = (char*)dg1->mrz.buf + 0;
            char* row_2 = (char*)dg1->mrz.buf + 30;

            snprintf(
                csv_line,
                sizeof(csv_line),
                "%.3s,%s,%.9s,%.6s,%.1s,%.6s\n",
                row_1 + 2,
                name,
                row_1 + 5,
                row_2,
                row_2 + 7,
                row_2 + 8);
        } else {
            FURI_LOG_W(TAG, "Unknown document type variant: %d", td_variant);
            storage_file_close(file);
            storage_file_free(file);
            furi_record_close(RECORD_STORAGE);
            furi_string_free(csv_path);
            return;
        }

        storage_file_write(file, csv_line, strlen(csv_line));
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(csv_path);
}

void save_com_to_file(void* context, BitBuffer* com_buffer, const char* name) {
    UNUSED(context);
    FuriString* path = furi_string_alloc();
    furi_string_printf(path, "%s/%s.com", STORAGE_APP_DATA_PATH_PREFIX, name);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = file_stream_alloc(storage);

    if(file_stream_open(stream, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        const uint8_t* data = bit_buffer_get_data(com_buffer);
        size_t size = bit_buffer_get_size_bytes(com_buffer);
        stream_write(stream, data, size);
    }

    file_stream_close(stream);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(path);
}

void passy_scene_read_success_on_enter(void* context) {
    Passy* passy = context;

    dolphin_deed(DolphinDeedNfcReadSuccess);
    notification_message(passy->notifications, &sequence_success);

    furi_string_reset(passy->text_box_store);
    FuriString* str = passy->text_box_store;
    if(passy->read_type == PassyReadDG1) {
        DG1_t* dg1 = 0;
        dg1 = calloc(1, sizeof *dg1);
        assert(dg1);
        asn_dec_rval_t rval = asn_decode(
            0,
            ATS_DER,
            &asn_DEF_DG1,
            (void**)&dg1,
            bit_buffer_get_data(passy->DG1),
            bit_buffer_get_size_bytes(passy->DG1));

        if(rval.code == RC_OK) {
            FURI_LOG_I(TAG, "ASN.1 decode success");

            char payloadDebug[384] = {0};
            memset(payloadDebug, 0, sizeof(payloadDebug));
            (&asn_DEF_DG1)
                ->op->print_struct(&asn_DEF_DG1, dg1, 1, print_struct_callback, payloadDebug);
            if(strlen(payloadDebug) > 0) {
                FURI_LOG_D(TAG, "DG1: %s", payloadDebug);
            } else {
                FURI_LOG_D(TAG, "Received empty Payload");
            }

            if(dg1->mrz.buf[0] == 'I' && dg1->mrz.buf[1] == 'P') {
                furi_string_cat_printf(str, "Passport card\n");
            } else if(dg1->mrz.buf[0] == 'I') {
                furi_string_cat_printf(str, "ID Card\n");
            } else if(dg1->mrz.buf[0] == 'P') {
                furi_string_cat_printf(str, "Passport book\n");
            } else if(dg1->mrz.buf[0] == 'A') {
                furi_string_cat_printf(str, "Residency Permit\n");
            } else {
                furi_string_cat_printf(str, "Unknown\n");
            }

            uint8_t td_variant = 0;
            if(dg1->mrz.size == 90) {
                td_variant = 1;
            } else if(dg1->mrz.size == 88) {
                td_variant = 3;
            } else {
                FURI_LOG_W(TAG, "MRZ length (%zu) is unexpected.", dg1->mrz.size);
            }

            char name[40] = {0};
            memset(name, 0, sizeof(name));
            uint8_t name_offset = td_variant == 3 ? 5 : 60;
            memcpy(name, dg1->mrz.buf + name_offset, 38);
            // Work backwards replace < at the end with \0
            for(size_t i = sizeof(name) - 1; i > 0; i--) {
                if(name[i] == '<') {
                    name[i] = '\0';
                } else {
                    break;
                }
            }
            // Work forwards replace < with space
            for(size_t i = 0; i < sizeof(name); i++) {
                if(name[i] == '<') {
                    name[i] = ' ';
                }
            }

            if(td_variant == 3) { // Passport form factor
                char* row_1 = (char*)dg1->mrz.buf + 0;
                char* row_2 = (char*)dg1->mrz.buf + 44;

                furi_string_cat_printf(str, "Country: %.3s\n", row_1 + 2);
                furi_string_cat_printf(str, "Name: %s\n", name);
                furi_string_cat_printf(str, "Doc Number: %.9s\n", row_2);
                furi_string_cat_printf(str, "DoB: %.6s\n", row_2 + 13);
                furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 20);
                furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 21);

                furi_string_cat_printf(str, "\n");
                furi_string_cat_printf(str, "Raw data:\n");
                furi_string_cat_printf(str, "%.44s\n", row_1);
                furi_string_cat_printf(str, "%.44s\n", row_2);
                save_dg1_to_file(passy, dg1, td_variant, name);
            } else if(td_variant == 1) { // ID form factor
                char* row_1 = (char*)dg1->mrz.buf + 0;
                char* row_2 = (char*)dg1->mrz.buf + 30;
                char* row_3 = (char*)dg1->mrz.buf + 60;

                furi_string_cat_printf(str, "Country: %.3s\n", row_1 + 2);
                furi_string_cat_printf(str, "Name: %s\n", name);
                furi_string_cat_printf(str, "Doc Number: %.9s\n", row_1 + 5);
                furi_string_cat_printf(str, "DoB: %.6s\n", row_2);
                furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 7);
                furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 8);

                furi_string_cat_printf(str, "\n");
                furi_string_cat_printf(str, "Raw data:\n");
                furi_string_cat_printf(str, "%.30s\n", row_1);
                furi_string_cat_printf(str, "%.30s\n", row_2);
                furi_string_cat_printf(str, "%.30s\n", row_3);
                save_dg1_to_file(passy, dg1, td_variant, name);
            }

        } else {
            FURI_LOG_E(TAG, "ASN.1 decode failed: %d.  %d consumed", rval.code, rval.consumed);
            furi_string_cat_printf(str, "%s\n", bit_buffer_get_data(passy->DG1));
        }

        free(dg1);
        dg1 = 0;

    } else if(passy->read_type == PassyReadDG2 || passy->read_type == PassyReadDG7) {
        furi_string_cat_printf(str, "Saved to disk in apps_data/passy/\n");
    } else if(passy->read_type == PassyReadCOM) {
        save_com_to_file(context, passy->DG1, passy->file_name);
        
        // Mostrar los Data Groups presentes
        const uint8_t* com_data = bit_buffer_get_data(passy->DG1);
        size_t com_size = bit_buffer_get_size_bytes(passy->DG1);
        
        FURI_LOG_I(TAG, "COM file size: %d bytes", com_size);
        FURI_LOG_I(TAG, "COM raw data:");
        for(size_t i = 0; i < com_size; i++) {
            FURI_LOG_I(TAG, "Byte %d: 0x%02X", i, com_data[i]);
        }
        
        // El archivo COM comienza con el tag '60' (Application level information)
        if(com_size > 4) {
            size_t offset = 0;
            
            // Buscar el tag '5F01' (LDS Version)
            while(offset < com_size - 2) {
                if(com_data[offset] == 0x5F && com_data[offset + 1] == 0x01) {
                    FURI_LOG_I(TAG, "Found tag 5F01 at offset %d", offset);
                    // El siguiente byte es la longitud (debe ser 0x04)
                    if(com_data[offset + 2] == 0x04) {
                        // Los siguientes 4 bytes contienen la versión LDS
                        uint8_t major = com_data[offset + 3];
                        uint8_t minor = com_data[offset + 4];
                        furi_string_cat_printf(str, "LDS Version: %02d.%02d\n", major, minor);
                    }
                    break;
                }
                offset++;
            }
            
            // Buscar el tag '5F36' (Unicode Version)
            offset = 0;
            while(offset < com_size - 2) {
                if(com_data[offset] == 0x5F && com_data[offset + 1] == 0x36) {
                    FURI_LOG_I(TAG, "Found tag 5F36 at offset %d", offset);
                    // El siguiente byte es la longitud (debe ser 0x06)
                    if(com_data[offset + 2] == 0x06) {
                        // Los siguientes 6 bytes contienen la versión Unicode
                        uint8_t major = com_data[offset + 3];
                        uint8_t minor = com_data[offset + 4];
                        uint8_t release = com_data[offset + 5];
                        furi_string_cat_printf(str, "Unicode Version: %02d.%02d.%02d\n", major, minor, release);
                    }
                    break;
                }
                offset++;
            }
            
            // Buscar el tag '5C' (Lista de DG presentes)
            offset = 0;
            while(offset < com_size - 1) {
                if(com_data[offset] == 0x5C) {
                    FURI_LOG_I(TAG, "Found tag 5C at offset %d", offset);
                    // El siguiente byte es la longitud
                    uint8_t length = com_data[offset + 1];
                    FURI_LOG_I(TAG, "Length after 5C: %d", length);
                    
                    furi_string_cat_printf(str, "\nData Groups presentes:\n");
                    // Cada byte en la lista representa un DG
                    for(size_t i = 0; i < length && (offset + 2 + i) < com_size; i++) {
                        uint8_t dg_tag = com_data[offset + 2 + i];
                        FURI_LOG_I(TAG, "DG tag at offset %d: 0x%02X", offset + 2 + i, dg_tag);
                        
                        // Convertir el tag al número de DG
                        switch(dg_tag) {
                            case 0x61: furi_string_cat_printf(str, "- DG1 (MRZ)\n"); break;
                            case 0x75: furi_string_cat_printf(str, "- DG2 (Foto)\n"); break;
                            case 0x63: furi_string_cat_printf(str, "- DG3 (Huellas)\n"); break;
                            case 0x76: furi_string_cat_printf(str, "- DG4 (Iris)\n"); break;
                            case 0x65: furi_string_cat_printf(str, "- DG5 (Imagen facial)\n"); break;
                            case 0x66: furi_string_cat_printf(str, "- DG6 (Dirección)\n"); break;
                            case 0x67: furi_string_cat_printf(str, "- DG7 (Firma)\n"); break;
                            case 0x68: furi_string_cat_printf(str, "- DG8 (Certificado)\n"); break;
                            default: furi_string_cat_printf(str, "- DG desconocido (0x%02X)\n", dg_tag); break;
                        }
                    }
                    break;
                }
                offset++;
            }
            
            furi_string_cat_printf(str, "\n");
        }
    }
    text_box_set_font(passy->text_box, TextBoxFontText);
    text_box_set_text(passy->text_box, furi_string_get_cstr(passy->text_box_store));
    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewTextBox);
}

bool passy_scene_read_success_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
    } else if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            passy->scene_manager, PassySceneMainMenu);
        consumed = true;
    }
    return consumed;
}

void passy_scene_read_success_on_exit(void* context) {
    Passy* passy = context;

    // Clear view
    text_box_reset(passy->text_box);
}
