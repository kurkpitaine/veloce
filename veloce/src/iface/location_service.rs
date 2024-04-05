use crate::config::GN_LOCATION_SERVICE_MAX_REQS;
use crate::time::Instant;
use crate::wire::GnAddress;

use heapless::Vec;

type LsRequests = Vec<Option<LocationServiceRequest>, GN_LOCATION_SERVICE_MAX_REQS>;

/// Error returned by [`AccessHandler::ls_request`]
pub enum LocationServiceRequestError {
    /// No slot available for the request.
    /// Number of pending requests is at maximum.
    NoFreeSlot,
}

/// Location Service request entry.
#[derive(Debug)]
pub struct LocationServiceRequest {
    /// State of the request.
    pub state: LocationServiceState,
}

/// State of a Location Service request.
#[derive(Debug)]
pub enum LocationServiceState {
    /// Location Service request is pending.
    Pending(LocationServicePendingRequest),
    /// Location Service request has failed.
    Failure(LocationServiceFailedRequest),
}

/// State of a pending Location Service request.
#[derive(Debug)]
pub struct LocationServicePendingRequest {
    /// Geonetworking address of the requested position.
    pub address: GnAddress,
    /// Timestamp at which we need to retransmit the location request.
    pub retransmit_at: Instant,
    /// Number of attempts.
    pub attempts: u8,
}

/// State of a pending Location Service request.
#[derive(Debug)]
pub struct LocationServiceFailedRequest {
    /// Geonetworking address of the failed request.
    pub address: GnAddress,
}

/// A handle to an in-progress Location Request.
#[derive(Debug, Clone, Copy)]
pub struct LocationServiceRequestHandle(pub usize);

/// Location Service.
#[derive(Debug)]
pub struct LocationService {
    /// Location Service requests.
    pub ls_requests: LsRequests,
}

impl LocationService {
    /// Constructs a new [LocationService].
    pub fn new() -> Self {
        let mut storage = Vec::new();
        loop {
            if storage.push(None).is_err() {
                break;
            }
        }

        LocationService {
            ls_requests: storage,
        }
    }

    /// Return the minimum time the location service should be polled at.
    pub(crate) fn poll_at(&self) -> Option<Instant> {
        self.ls_requests
            .iter()
            .flatten()
            .filter_map(|item| match &item.state {
                LocationServiceState::Pending(p) => Some(p.retransmit_at),
                LocationServiceState::Failure(_) => None,
            })
            .min()
    }

    /// Finds the first free slot available for the Location Service.
    pub fn ls_find_free_handle(&mut self) -> Option<LocationServiceRequestHandle> {
        for (i, q) in self.ls_requests.iter().enumerate() {
            if q.is_none() {
                return Some(LocationServiceRequestHandle(i));
            }
        }

        None
    }

    /// Start a new Location Service request to `address`.
    ///
    /// The first request attempt is scheduled immediately.
    pub fn request(
        &mut self,
        address: GnAddress,
        timestamp: Instant,
    ) -> Result<LocationServiceRequestHandle, LocationServiceRequestError> {
        let handle = self
            .ls_find_free_handle()
            .ok_or(LocationServiceRequestError::NoFreeSlot)?;

        self.ls_requests[handle.0] = Some(LocationServiceRequest {
            state: LocationServiceState::Pending(LocationServicePendingRequest {
                address,
                retransmit_at: timestamp,
                attempts: 0,
            }),
        });

        Ok(handle)
    }

    /// Cancels a request, freeing the slot.
    ///
    /// # Panics
    ///
    /// Panics if the LocationServiceRequestHandle corresponds to an already free slot.
    pub fn cancel_request(&mut self, handle: LocationServiceRequestHandle) {
        let slot = &mut self.ls_requests[handle.0];
        if slot.is_none() {
            panic!("Canceling request in a free slot.")
        }
        *slot = None; // Free up the slot for recycling.
    }
}
