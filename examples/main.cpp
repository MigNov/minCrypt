#include <wx/wx.h>
#include "mincrypt.h"
#include "interface.h"

IMPLEMENT_APP(MinCrypt)

bool MinCrypt::OnInit()
{
	MainFrame *frame = new MainFrame( _("MinCrypt GUI"), wxDefaultPosition,
						wxSize(530, 260));

	frame->Connect( ID_Quit, wxEVT_COMMAND_MENU_SELECTED,
			(wxObjectEventFunction) &MainFrame::OnQuit );
	frame->Connect( ID_About, wxEVT_COMMAND_MENU_SELECTED,
			(wxObjectEventFunction) &MainFrame::OnAbout );
	frame->Connect( ID_OpenInput, wxEVT_COMMAND_BUTTON_CLICKED,
			(wxObjectEventFunction) &MainFrame::OnOpenInput );
	frame->Connect( ID_SaveOutput, wxEVT_COMMAND_BUTTON_CLICKED,
			(wxObjectEventFunction) &MainFrame::OnSaveOutput );
	frame->Connect( ID_Process, wxEVT_COMMAND_BUTTON_CLICKED,
			(wxObjectEventFunction) &MainFrame::OnProcess );
    
	frame->Show(true);
	SetTopWindow(frame);
	return true;
}

void AddLayoutLine(int type, wxPanel *panel, wxBoxSizer *vbox, wxString title, void *data, int id)
{
	wxTextCtrl **tc = NULL;
	wxCheckBox **cb = NULL;

	wxBoxSizer *pan1 = new wxBoxSizer(wxHORIZONTAL);
	if (type < 2) {
		tc = (wxTextCtrl **)data;
		wxStaticText *st1 =  new wxStaticText(panel, wxID_ANY, title, wxDefaultPosition, wxSize(150, 20), wxST_NO_AUTORESIZE | wxALIGN_RIGHT);
		pan1->Add(st1, 0, wxTOP | wxRIGHT, 5);
	}
	else {
		cb = (wxCheckBox **)data;
	}

	if (type == 0) { // Password TextCtrl
		*tc = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxSize(350, 30), wxTE_PASSWORD);
		pan1->Add(*tc, 0, wxRIGHT, 5);
	}
	else
	if (type == 1) { // Browse
		*tc = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxSize(250, 30));
		pan1->Add(*tc, 0, wxRIGHT, 5);
		wxButton *btn1 = new wxButton(panel, id, _("Browse"), wxDefaultPosition, wxSize(100, 30) );
		pan1->Add(btn1, 0);
	}
	else
	if (type == 2) { // Select type and process
		*cb = new wxCheckBox(panel, id, _("Decrypt file (instead of encryption)"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT);
		pan1->Add(*cb, 0, wxRIGHT, 135);
		wxButton *btn1 = new wxButton(panel, id, title, wxDefaultPosition, wxSize(100, 30) );
		pan1->Add(btn1, 0);
	}
	vbox->Add(pan1, 0, wxLEFT | wxTOP, 10);
}

MainFrame::MainFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
	: wxFrame( NULL, -1, title, pos, size, wxMINIMIZE_BOX | wxMAXIMIZE_BOX | wxSYSTEM_MENU | wxCAPTION | wxCLOSE_BOX | wxCLIP_CHILDREN)
{
	wxMenuBar *menuBar = new wxMenuBar;
	wxMenu *menuFile = new wxMenu;
	wxPanel *panel = new wxPanel(this, -1);
	wxBoxSizer *vbox = new wxBoxSizer(wxVERTICAL);

	menuFile->Append( ID_About, _("&About...") );
	menuFile->AppendSeparator();
	menuFile->Append( ID_Quit, _("E&xit") );

	menuBar->Append(menuFile, _("&File") );

	SetMenuBar(menuBar);

	CreateStatusBar();
	Centre();

	AddLayoutLine(1, panel, vbox, wxT("Input file name:"), &inf, ID_OpenInput);
	AddLayoutLine(1, panel, vbox, wxT("Output file name:"), &outf, ID_SaveOutput);
	AddLayoutLine(0, panel, vbox, wxT("Salt: "), &salt, wxID_ANY);
	AddLayoutLine(0, panel, vbox, wxT("Password: "), &pwd, wxID_ANY);
	AddLayoutLine(2, panel, vbox, wxT("Process"), &dec, ID_Process);

	panel->SetSizer(vbox);
	SetStatusText( _("MinCrypt v0.0.1") );
}

void MainFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
	Close(true);
}

void MainFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
	wxMessageBox( _("Written in wxWidgets by Michal Novotny, MinCrypt author.\n"
			"For more information please see project website at:\n"
			"http://www.migsoft.net/projects/minCrypt\n\n"
			"For development snapshot please see project git repo at:\n"
			"http://github.com/MigNov/minCrypt"), 
		_("About MinCrypt GUI"),
		wxOK|wxICON_INFORMATION, this );
}

void MainFrame::OnOpenInput(wxCommandEvent& WXUNUSED(event))
{
	wxString fn = wxEmptyString;

	fn = selectFileName(this, 0);
	if (fn != wxEmptyString)
		inf->ChangeValue(fn);
}

void MainFrame::OnSaveOutput(wxCommandEvent& WXUNUSED(event))
{
	wxString fn = wxEmptyString;

	fn = selectFileName(this, 1);
	if (fn != wxEmptyString)
		outf->ChangeValue(fn);
}

void MainFrame::OnProcess(wxCommandEvent& WXUNUSED(event))
{
	wxString infile = inf->GetLineText(0);
	wxString outfile = outf->GetLineText(0);
	wxString saltv = salt->GetLineText(0);
	wxString pwdv = pwd->GetLineText(0);
	int type = dec->IsChecked() ? 1 : 0;
	int rc;

	/*
	wxMessageDialog *dial = new wxMessageDialog(NULL, wxT("Are you sure about file encryption?"), wxT("Encrypt?"), wxYES_NO | wxICON_ERROR);
	if (dial->ShowModal() != wxID_YES)
		return;
 	*/

	if (type == 0)
		rc = crypt_encrypt_file(wxStringChar(infile), wxStringChar(outfile), wxStringChar(saltv), wxStringChar(pwdv), vect_mult);
	else
		rc = crypt_decrypt_file(wxStringChar(infile), wxStringChar(outfile), wxStringChar(saltv), wxStringChar(pwdv), vect_mult);

	if (rc != 0)
		SetStatusText( wxString::Format(_T("File operation returned code %d"), rc) );
	else
		SetStatusText( wxString::Format(_T("File operation completed successfully")) );
}

