package vbox

import (
	"net"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/akutz/gofig"
	"github.com/akutz/goof"
	vbox "github.com/appropriate/go-virtualboxclient/virtualboxclient"
	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/api/types/context"
	"github.com/emccode/libstorage/api/types/drivers"
	"github.com/emccode/libstorage/drivers/storage/vbox/executor"
)

const (
	// Name is the name of the driver.
	Name = executor.Name
)

type driver struct {
	exec *executor.Executor
	sync.Mutex
	config         gofig.Config
	vbox           *vbox.VirtualBox
	machine        *vbox.Machine
	machineNameID  string
	uname          string
	passwd         string
	endpoint       string
	volumePath     string
	useTLS         bool
	controllerName string
}

func init() {
	gofig.Register(executor.LoadConfig())
	registry.RegisterStorageDriver(Name, newDriver)
}

func newDriver() drivers.StorageDriver {
	return &driver{}
}

// Name returns the name of the driver
func (d *driver) Name() string {
	return Name
}

// Init initializes the driver.
func (d *driver) Init(config gofig.Config) error {
	d.exec = &executor.Executor{}
	d.config = config
	d.uname = d.config.GetString("virtualbox.username")
	d.passwd = d.config.GetString("virtualbox.username")
	d.endpoint = d.config.GetString("virtualbox.endpoint")
	d.volumePath = d.config.GetString("virtualbox.volumePath")
	d.useTLS = d.config.GetBool("virtualbox.tls")
	d.machineNameID = d.config.GetString("virtualbox.nameOrId")

	fields := map[string]interface{}{
		"provider":        Name,
		"moduleName":      Name,
		"endpoint":        d.endpoint,
		"userName":        d.uname,
		"tls":             d.useTLS,
		"volumePath":      d.volumePath,
		"machineNameOrId": d.machineNameID,
	}

	d.vbox = vbox.New(d.uname, d.passwd,
		d.endpoint, d.useTLS, d.controllerName)

	if err := d.vboxLogon(); err != nil {
		return goof.WithFieldsE(fields,
			"error logging in", err)
	}

	if m, err := d.findLocalMachine(d.machineNameID); err != nil {
		goof.WithFieldsE(fields,
			"failed to find local machine", err)
	} else {
		d.machine = m
	}

	log.WithFields(fields).Info("storage driver initialized")
	return nil
}

func (d *driver) InstanceID(
	ctx context.Context,
	opts types.Store) (*types.InstanceID, error) {
	return &types.InstanceID{ID: d.machine.ID}, nil
}

// NextDevice returns the next available device.
func (d *driver) NextDevice(
	ctx context.Context,
	opts types.Store) (string, error) {
	return d.exec.NextDevice(ctx, opts)
}

// LocalDevices returns a map of the system's local devices.
func (d *driver) LocalDevices(
	ctx context.Context,
	opts types.Store) (map[string]string, error) {
	return d.exec.LocalDevices(ctx, opts)
}

func (d *driver) Type() types.StorageType {
	return types.Block
}

// ??
func (d *driver) NextDeviceInfo() *types.NextDeviceInfo {
	return nil
}

func (d *driver) InstanceInspect(
	ctx context.Context,
	opts types.Store) (*types.Instance, error) {
	instanceID, _ := d.InstanceID(ctx, opts)
	return &types.Instance{InstanceID: instanceID}, nil
}

func (d *driver) Volumes(
	ctx context.Context,
	opts *drivers.VolumesOpts) ([]*types.Volume, error) {
	d.Lock()
	defer d.Unlock()
	d.refreshSession()

	if err := d.machine.Refresh(); err != nil {
		return nil, err
	}
	defer d.machine.Release()

	mapDiskByID, err := d.exec.LocalDevices(ctx, nil)
	if err != nil {
		return nil, err
	}

	mas, err := d.machine.GetMediumAttachments()
	if err != nil {
		return nil, err
	}

	var blockDevices []*types.Volume
	for _, ma := range mas {
		medium := d.vbox.NewMedium(ma.Medium)
		defer medium.Release()

		mid, err := medium.GetID()
		if err != nil {
			return nil, err
		}
		smid := strings.Split(mid, "-")
		if len(smid) == 0 {
			continue
		}

		location, err := medium.GetLocation()
		if err != nil {
			return nil, err
		}

		var bdn string
		var ok bool
		if bdn, ok = mapDiskByID[smid[0]]; !ok {
			continue
		}
		sdBlockDevice := &types.Volume{
			Name:   bdn,
			ID:     mid,
			Status: location,
		}
		blockDevices = append(blockDevices, sdBlockDevice)

	}
	return blockDevices, nil
}

func (d *driver) VolumeInspect(
	ctx context.Context,
	volumeID string,
	opts *drivers.VolumeInspectOpts) (*types.Volume, error) {
	return nil, nil
}

func (d *driver) VolumeCreate(
	ctx context.Context,
	name string,
	opts *drivers.VolumeCreateOpts) (*types.Volume, error) {

	if opts.Size == nil {
		return nil, goof.New("missing volume size")
	}

	fields := map[string]interface{}{
		"provider":   Name,
		"volumeName": name,
		"size":       *opts.Size,
	}

	size := *opts.Size * 1024 * 1024 * 1024

	d.refreshSession()
	volumes, err := d.vbox.GetMedium("", name)
	if err != nil {
		return nil, err
	}

	if len(volumes) > 0 {
		return nil, goof.WithFields(fields, "volume exists already")
	}

	volume, err := d.createVolume(name, size)
	if err != nil {
		return nil, goof.WithFieldsE(fields, "error creating new volume", err)
	}

	// double check
	volumes, err = d.vbox.GetMedium(volume.ID, "")
	if err != nil {
		return nil, err
	}

	if len(volumes) == 0 {
		return nil, goof.New("failed to get new volume")
	}

	newVol := &types.Volume{
		ID:   volume.ID,
		Name: volume.Name,
		Size: volume.Size,
		IOPS: *opts.IOPS,
		Type: string(volume.DeviceType),
	}

	return newVol, nil
}

func (d *driver) VolumeCreateFromSnapshot(
	ctx context.Context,
	snapshotID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	return nil, types.ErrNotImplemented
}

func (d *driver) VolumeCopy(
	ctx context.Context,
	volumeID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	return nil, nil
}

func (d *driver) VolumeSnapshot(
	ctx context.Context,
	volumeID, snapshotName string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, types.ErrNotImplemented
}

func (d *driver) VolumeRemove(
	ctx context.Context,
	volumeID string,
	opts types.Store) error {

	d.Lock()
	defer d.Unlock()
	d.refreshSession()

	fields := map[string]interface{}{
		"provider": Name,
		"volumeID": volumeID,
	}

	err := d.vbox.RemoveMedium(volumeID)
	if err != nil {
		return goof.WithFieldsE(fields, "error deleting volume", err)
	}

	return nil
}

func (d *driver) VolumeAttach(
	ctx context.Context,
	volumeID string,
	opts *drivers.VolumeAttachByIDOpts) (*types.Volume, error) {
	return nil, nil
}

func (d *driver) VolumeDetach(
	ctx context.Context,
	volumeID string,
	opts types.Store) error {
	return nil
}

func (d *driver) Snapshots(
	ctx context.Context,
	opts types.Store) ([]*types.Snapshot, error) {
	return nil, nil
}

func (d *driver) SnapshotInspect(
	ctx context.Context,
	snapshotID string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, nil
}

func (d *driver) SnapshotCopy(
	ctx context.Context,
	snapshotID, snapshotName, destinationID string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, nil
}

func (d *driver) SnapshotRemove(
	ctx context.Context,
	snapshotID string,
	opts types.Store) error {
	return nil
}

func (d *driver) vboxLogon() error {
	if d.volumePath == "" {
		return goof.New("missing volume path")
	}

	if d.endpoint == "" {
		return goof.New("missing endpoint")
	}

	if err := d.vbox.Logon(); err != nil {
		return err
	}
	return nil
}

func (d *driver) findLocalMachine(nameOrID string) (*vbox.Machine, error) {
	d.Lock()
	defer d.Unlock()

	if nameOrID != "" {
		m, err := d.vbox.FindMachine(nameOrID)
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, goof.New("could not find machine")
		}

		if id, err := m.GetID(); err == nil {
			m.ID = id
		} else {
			return nil, err
		}

		if name, err := m.GetName(); err == nil {
			m.Name = name
		} else {
			return nil, err
		}

		return m, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	macMap := make(map[string]bool)
	for _, intf := range interfaces {
		macUp := strings.ToUpper(strings.Replace(intf.HardwareAddr.String(), ":", "", -1))
		macMap[macUp] = true
	}

	machines, err := d.vbox.GetMachines()
	if err != nil {
		return nil, err
	}

	sp, err := d.vbox.GetSystemProperties()
	if err != nil {
		return nil, err
	}
	defer sp.Release()

	for _, m := range machines {
		defer m.Release()
		chipset, err := m.GetChipsetType()
		if err != nil {
			return nil, err
		}

		mna, err := sp.GetMaxNetworkAdapters(chipset)
		if err != nil {
			return nil, err
		}

		for i := uint32(0); i < mna; i++ {
			na, err := m.GetNetworkAdapter(i)
			if err != nil {
				return nil, err
			}

			mac, err := na.GetMACAddress()
			if err != nil {
				return nil, err
			}

			if _, ok := macMap[mac]; ok {
				id, err := m.GetID()
				if err != nil {
					return nil, err
				}
				m.ID = id

				name, err := m.GetName()
				if err != nil {
					return nil, err
				}
				m.Name = name

				return m, nil
			}
		}
	}
	return nil, goof.New("Unable to find machine")
}

// TODO too costly, need better way to validate session (i.e. some delay)
func (d *driver) refreshSession() {
	_, err := d.vbox.FindMachine(d.machine.ID)
	if err != nil {
		log.Debug("logging in again")
		d.vboxLogon()
	}
}

func (d *driver) createVolume(name string, size int64) (*vbox.Medium, error) {
	d.Lock()
	defer d.Unlock()
	d.refreshSession()

	if name == "" {
		return nil, goof.New("name is empty")
	}
	path := filepath.Join(d.volumePath, name)
	return d.vbox.CreateMedium("vmdk", path, size)
}
