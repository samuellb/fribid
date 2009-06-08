#define _BSD_SOURCE 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>

#include <unistd.h> // For STDIN_FILENO

#include "bankid.h"
#include "keyfile.h"
#include "platform.h"

void platform_init(int *argc, char ***argv) {
    gtk_init(argc, argv);
}

static gboolean pipeCallback(GIOChannel *source,
                             GIOCondition condition, gpointer data) {
    fprintf(stderr, "pipe callback\n");
    ((PlatformPipeFunction*)data)();
    return TRUE;
}

void platform_setupPipe(PlatformPipeFunction *pipeFunction) {
    GIOChannel *stdinChannel = g_io_channel_unix_new(STDIN_FILENO);
    
    g_io_add_watch(stdinChannel,
                   G_IO_IN | G_IO_HUP | G_IO_ERR, pipeCallback, (void*)pipeFunction);
    g_io_channel_unref(stdinChannel);
}

void platform_mainloop() {
    gtk_main();
}

/* Authentication */
static GtkDialog *signDialog;
static GtkComboBox *signaturesCombo;
static GtkEntry *passwordEntry;

void platform_startAuthenticate(const char *url, const char *hostname, const char *ip) {
    GtkBuilder *builder = gtk_builder_new();
    GError *error = NULL;
    
    if (!gtk_builder_add_from_file(builder, "/home/samuellb/Projekt/e-leg/main/gtk/bankid.xml", &error)) {
        fprintf(stderr, "bankid-se: Failed to open GtkBuilder XML: %s\n", error->message);
        g_error_free(error);
        return;
    }
    
    gtk_label_set_text(GTK_LABEL(gtk_builder_get_object(builder, "header_domain")),
                       hostname);
    
    gtk_widget_hide(GTK_WIDGET(gtk_builder_get_object(builder, "sign_label")));
    gtk_widget_hide(GTK_WIDGET(gtk_builder_get_object(builder, "sign_scroller")));
    
    // Create a GtkListStore of (displayname, person, filename) tuples
    GtkListStore *signatures = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkTreeIter iter;
    iter.stamp = 0;
    
    PlatformDirIter *dir = platform_openKeysDir();
    while (platform_iterateDir(dir)) {
        char *filename = platform_currentPath(dir);
        int fileLen;
        char *fileData;
        platform_readFile(filename, &fileData, &fileLen);
        
        int personCount;
        char **people = NULL;
        keyfile_listPeople(fileData, fileLen, &people, &personCount);
        
        for (int i = 0; i < personCount; i++) {
            char *displayName = keyfile_getDisplayName(people[i]);
            
            gtk_list_store_append(signatures, &iter);
            gtk_list_store_set(signatures, &iter,
                               0, displayName,
                               1, people[i],
                               2, filename, -1);
            
            free(displayName);
            free(people[i]);
        }
        free(people);
        free(filename);
    }
    platform_closeDir(dir);
    
    signaturesCombo = GTK_COMBO_BOX(gtk_builder_get_object(builder, "signature_combo"));
    gtk_combo_box_set_model(signaturesCombo, GTK_TREE_MODEL(signatures));
    g_object_unref(signatures);
    
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(signaturesCombo),
                               renderer, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(signaturesCombo),
                                   renderer, "text", 0, NULL);
    
    passwordEntry = GTK_ENTRY(gtk_builder_get_object(builder, "password_entry"));
    
    signDialog = GTK_DIALOG(gtk_builder_get_object(builder, "dialog_sign"));
    //gtk_window_set_transient_for(GTK_WINDOW(signDialog), ???);
    gtk_window_set_keep_above(GTK_WINDOW(signDialog), TRUE);
}

void platform_endAuthenticate() {
    gtk_widget_destroy(GTK_WIDGET(signDialog));
}

bool platform_authenticate(char **signature, int *siglen, char **person, char **password) {
    
    if (gtk_dialog_run(signDialog) == 10) {
        // User pressed "Log in" or "Sign"
        GtkTreeIter iter;
        iter.stamp = 0;
        
        *signature = NULL;
        *siglen = 0;
        *person = NULL;
        
        if (gtk_combo_box_get_active_iter(signaturesCombo, &iter)) {
            char *filename;
            GtkTreeModel *model = gtk_combo_box_get_model(signaturesCombo);
            gtk_tree_model_get(model, &iter,
                               1, person,
                               2, &filename, -1);
        
            // Read .p12 file
            platform_readFile(filename, signature, siglen);
            free(filename);
        }
        
        *password = strdup(gtk_entry_get_text(passwordEntry));
        return true;
        
    } else {
        // User pressed cancel or closed the dialog
        return false;
    }
}




